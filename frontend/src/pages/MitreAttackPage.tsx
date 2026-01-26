import {
  Box,
  Typography,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
  Chip,
  Grid,
  TextField,
  InputAdornment,
  Link,
  Alert,
  Button,
  Drawer,
  Fab,
  LinearProgress,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Tooltip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Collapse,
} from "@mui/material";
import { useState, useMemo, useEffect } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import BookIcon from "@mui/icons-material/Book";
import ChecklistIcon from "@mui/icons-material/Checklist";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import BuildIcon from "@mui/icons-material/Build";
import MeetingRoomIcon from "@mui/icons-material/MeetingRoom";
import FlashOnIcon from "@mui/icons-material/FlashOn";
import PushPinIcon from "@mui/icons-material/PushPin";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import ExploreIcon from "@mui/icons-material/Explore";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import InventoryIcon from "@mui/icons-material/Inventory";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import WarningIcon from "@mui/icons-material/Warning";
import SettingsIcon from "@mui/icons-material/Settings";
import DataUsageIcon from "@mui/icons-material/DataUsage";
import LinkIcon from "@mui/icons-material/Link";

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

const operationalGuides = [
  {
    title: "Prioritize what matters",
    color: "#dc2626",
    points: [
      "Start with tactics that threaten crown jewel assets",
      "Use threat intel to focus on likely adversaries",
      "Scope coverage by environment: on-prem, cloud, and SaaS",
    ],
  },
  {
    title: "Build detections per technique",
    color: "#f59e0b",
    points: [
      "Map each detection rule to a technique ID",
      "Identify required data sources before writing logic",
      "Document expected false positives and tuning steps",
    ],
  },
  {
    title: "Validate with emulation",
    color: "#3b82f6",
    points: [
      "Run atomic tests or purple team exercises",
      "Capture telemetry and confirm alert fidelity",
      "Record gaps as backlog items with owners",
    ],
  },
  {
    title: "Operationalize in response",
    color: "#8b5cf6",
    points: [
      "Attach playbooks to high risk techniques",
      "Train analysts on pivots and scoping",
      "Use ATT&CK in incident reports and lessons learned",
    ],
  },
];

const telemetrySources = [
  "Process creation and command line logs",
  "Network flow, proxy, and DNS telemetry",
  "Authentication and identity provider events",
  "Endpoint file, registry, and module loads",
  "Cloud audit and API activity logs",
  "Email gateway and collaboration telemetry",
];

const validationSteps = [
  "Execute technique simulations and capture evidence",
  "Confirm detections trigger with real telemetry",
  "Measure time to detect and contain",
  "Tune noise and document alert context",
];

const reportingMetrics = [
  "Technique coverage heatmaps by tactic",
  "High risk technique backlog with owners",
  "Playbooks mapped to critical techniques",
  "Coverage by critical assets and environments",
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#3b82f6";
const ACCENT_COLOR = "#dc2626";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "ATT&CK stands for:",
    options: ["Adversarial Tactics, Techniques, and Common Knowledge", "Advanced Threat Tracking and Control Kit", "Attack Tools and Threat Checklist", "Applied Tactics and Threat Catalog"],
    correctAnswer: 0,
    explanation: "ATT&CK is the MITRE knowledge base of adversary behavior.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "A tactic describes:",
    options: ["The adversary goal or why", "The exact exploit code", "The CVE identifier", "The patch schedule"],
    correctAnswer: 0,
    explanation: "Tactics represent objectives like initial access or exfiltration.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "A technique describes:",
    options: ["How the adversary achieves a tactic", "Why the attacker acts", "The severity score", "The firewall rule"],
    correctAnswer: 0,
    explanation: "Techniques are the methods used to accomplish tactics.",
  },
  {
    id: 4,
    topic: "Identifiers",
    question: "Technique IDs start with:",
    options: ["T", "TA", "G", "S"],
    correctAnswer: 0,
    explanation: "Techniques are labeled T####.",
  },
  {
    id: 5,
    topic: "Identifiers",
    question: "Tactic IDs start with:",
    options: ["TA", "T", "G", "S"],
    correctAnswer: 0,
    explanation: "Tactics are labeled TA####.",
  },
  {
    id: 6,
    topic: "Identifiers",
    question: "Sub-techniques are shown as:",
    options: ["T1059.001", "TA1059", "S1059", "G1059"],
    correctAnswer: 0,
    explanation: "Sub-techniques use a dot notation.",
  },
  {
    id: 7,
    topic: "Matrices",
    question: "The ATT&CK matrices include:",
    options: ["Enterprise, Mobile, and ICS", "Web, Cloud, and IoT only", "Linux and Windows only", "Email and DNS only"],
    correctAnswer: 0,
    explanation: "ATT&CK covers Enterprise, Mobile, and ICS.",
  },
  {
    id: 8,
    topic: "Use",
    question: "ATT&CK is primarily used to:",
    options: ["Map adversary behaviors and defenses", "Assign CVEs", "Configure firewalls", "Patch operating systems"],
    correctAnswer: 0,
    explanation: "It helps map behaviors, detections, and gaps.",
  },
  {
    id: 9,
    topic: "Use",
    question: "Coverage mapping helps teams:",
    options: ["Identify detection gaps", "Disable alerts", "Remove logs", "Skip tuning"],
    correctAnswer: 0,
    explanation: "Mapping shows which techniques lack coverage.",
  },
  {
    id: 10,
    topic: "Use",
    question: "The ATT&CK Navigator is used to:",
    options: ["Visualize and annotate coverage", "Scan vulnerabilities", "Encrypt logs", "Block traffic"],
    correctAnswer: 0,
    explanation: "Navigator helps visualize technique coverage.",
  },
  {
    id: 11,
    topic: "Tactics",
    question: "Initial Access is a tactic focused on:",
    options: ["Gaining entry into a network", "Encrypting files", "Erasing logs", "Disabling monitoring"],
    correctAnswer: 0,
    explanation: "Initial Access covers entry methods.",
  },
  {
    id: 12,
    topic: "Tactics",
    question: "Execution is a tactic focused on:",
    options: ["Running malicious code", "Sending phishing emails", "Exfiltrating data", "Scanning ports"],
    correctAnswer: 0,
    explanation: "Execution covers code running on a system.",
  },
  {
    id: 13,
    topic: "Tactics",
    question: "Persistence is a tactic focused on:",
    options: ["Maintaining access over time", "Gathering user info", "Blocking network traffic", "Cleaning logs"],
    correctAnswer: 0,
    explanation: "Persistence keeps access after restarts.",
  },
  {
    id: 14,
    topic: "Tactics",
    question: "Privilege Escalation is focused on:",
    options: ["Gaining higher-level permissions", "Exfiltration", "Initial access", "Reconnaissance"],
    correctAnswer: 0,
    explanation: "Privilege escalation raises permissions.",
  },
  {
    id: 15,
    topic: "Tactics",
    question: "Defense Evasion is focused on:",
    options: ["Avoiding detection and controls", "Only collecting data", "Only scanning ports", "Only phishing"],
    correctAnswer: 0,
    explanation: "Defense evasion hides attacker activity.",
  },
  {
    id: 16,
    topic: "Tactics",
    question: "Credential Access is focused on:",
    options: ["Stealing credentials", "Encrypting disks", "User training", "Firewall tuning"],
    correctAnswer: 0,
    explanation: "Credential access targets passwords and tokens.",
  },
  {
    id: 17,
    topic: "Tactics",
    question: "Discovery is focused on:",
    options: ["Learning about the environment", "Installing persistence", "Exfiltrating data", "Encrypting files"],
    correctAnswer: 0,
    explanation: "Discovery maps hosts, users, and networks.",
  },
  {
    id: 18,
    topic: "Tactics",
    question: "Lateral Movement is focused on:",
    options: ["Moving between systems", "Phishing users", "Running scripts", "Encrypting data"],
    correctAnswer: 0,
    explanation: "Lateral movement spreads access.",
  },
  {
    id: 19,
    topic: "Tactics",
    question: "Collection is focused on:",
    options: ["Gathering data of interest", "Blocking C2", "Patching systems", "Deleting logs"],
    correctAnswer: 0,
    explanation: "Collection gathers data before exfiltration.",
  },
  {
    id: 20,
    topic: "Tactics",
    question: "Command and Control is focused on:",
    options: ["Establishing remote communication", "Delivering emails", "Scanning ports", "Deploying patches"],
    correctAnswer: 0,
    explanation: "C2 enables attacker control.",
  },
  {
    id: 21,
    topic: "Tactics",
    question: "Exfiltration is focused on:",
    options: ["Stealing data out of the network", "Executing scripts", "Gaining initial access", "Collecting logs"],
    correctAnswer: 0,
    explanation: "Exfiltration is data theft.",
  },
  {
    id: 22,
    topic: "Tactics",
    question: "Impact is focused on:",
    options: ["Disrupting availability or integrity", "Reconnaissance", "Initial access", "Collection"],
    correctAnswer: 0,
    explanation: "Impact covers damage like ransomware or sabotage.",
  },
  {
    id: 23,
    topic: "Technique",
    question: "T1059 is:",
    options: ["Command and Scripting Interpreter", "Credential Dumping", "Phishing", "Lateral Tool Transfer"],
    correctAnswer: 0,
    explanation: "T1059 covers scripting and command execution.",
  },
  {
    id: 24,
    topic: "Technique",
    question: "T1566 is:",
    options: ["Phishing", "Valid Accounts", "Data Encrypted for Impact", "Remote Services"],
    correctAnswer: 0,
    explanation: "T1566 covers phishing techniques.",
  },
  {
    id: 25,
    topic: "Technique",
    question: "T1003 is:",
    options: ["Credential Dumping", "Exfiltration Over C2", "System Information Discovery", "Screen Capture"],
    correctAnswer: 0,
    explanation: "T1003 covers credential dumping.",
  },
  {
    id: 26,
    topic: "Technique",
    question: "T1071 is:",
    options: ["Application Layer Protocol", "Ingress Tool Transfer", "System Service Discovery", "Spearphishing Link"],
    correctAnswer: 0,
    explanation: "T1071 covers C2 over common protocols.",
  },
  {
    id: 27,
    topic: "Technique",
    question: "T1021 is:",
    options: ["Remote Services", "Process Injection", "Registry Run Keys", "Data from Local System"],
    correctAnswer: 0,
    explanation: "T1021 covers remote service access for lateral movement.",
  },
  {
    id: 28,
    topic: "Technique",
    question: "T1055 is:",
    options: ["Process Injection", "Screen Capture", "Network Sniffing", "Keylogging"],
    correctAnswer: 0,
    explanation: "T1055 covers process injection techniques.",
  },
  {
    id: 29,
    topic: "Technique",
    question: "T1082 is:",
    options: ["System Information Discovery", "Account Discovery", "Clipboard Data", "Application Layer Protocol"],
    correctAnswer: 0,
    explanation: "T1082 covers system info discovery.",
  },
  {
    id: 30,
    topic: "Technique",
    question: "T1105 is:",
    options: ["Ingress Tool Transfer", "System Owner/User Discovery", "Remote File Copy", "Data from Cloud Storage"],
    correctAnswer: 0,
    explanation: "T1105 covers transferring tools into the environment.",
  },
  {
    id: 31,
    topic: "Technique",
    question: "T1486 is:",
    options: ["Data Encrypted for Impact", "Account Discovery", "Email Collection", "Disk Wipe"],
    correctAnswer: 0,
    explanation: "T1486 covers ransomware encryption.",
  },
  {
    id: 32,
    topic: "Technique",
    question: "T1041 is:",
    options: ["Exfiltration Over C2 Channel", "Credential Dumping", "Modify Registry", "Remote Services"],
    correctAnswer: 0,
    explanation: "T1041 is exfiltration over C2.",
  },
  {
    id: 33,
    topic: "Technique",
    question: "T1547 is:",
    options: ["Boot or Logon Autostart Execution", "Process Injection", "File Deletion", "Data from Local System"],
    correctAnswer: 0,
    explanation: "T1547 covers persistence via autostart.",
  },
  {
    id: 34,
    topic: "Technique",
    question: "T1110 is:",
    options: ["Brute Force", "Command and Scripting Interpreter", "Phishing", "System Information Discovery"],
    correctAnswer: 0,
    explanation: "T1110 covers brute force credential attempts.",
  },
  {
    id: 35,
    topic: "Technique",
    question: "T1204 is:",
    options: ["User Execution", "Exploit Public-Facing Application", "Remote Services", "Obfuscated Files or Information"],
    correctAnswer: 0,
    explanation: "T1204 covers user-driven execution.",
  },
  {
    id: 36,
    topic: "Technique",
    question: "T1567 is:",
    options: ["Exfiltration Over Web Service", "Application Layer Protocol", "Archive Collected Data", "Command and Control"],
    correctAnswer: 0,
    explanation: "T1567 covers exfiltration via web services.",
  },
  {
    id: 37,
    topic: "Technique",
    question: "T1033 is:",
    options: ["System Owner/User Discovery", "Permission Groups Discovery", "System Information Discovery", "Network Service Discovery"],
    correctAnswer: 0,
    explanation: "T1033 identifies logged in users.",
  },
  {
    id: 38,
    topic: "Technique",
    question: "T1018 is:",
    options: ["Remote System Discovery", "Spearphishing Attachment", "Data from Network Shared Drive", "Account Discovery"],
    correctAnswer: 0,
    explanation: "T1018 covers discovery of remote systems.",
  },
  {
    id: 39,
    topic: "Technique",
    question: "T1558 is:",
    options: ["Steal or Forge Kerberos Tickets", "Exfiltration Over C2", "Modify Registry", "Email Collection"],
    correctAnswer: 0,
    explanation: "T1558 covers Kerberos ticket abuse.",
  },
  {
    id: 40,
    topic: "Technique",
    question: "T1078 is commonly used for:",
    options: ["Valid Accounts", "Network Sniffing", "Exfiltration Over C2", "Data from Clipboard"],
    correctAnswer: 0,
    explanation: "T1078 covers use of valid credentials.",
  },
  {
    id: 41,
    topic: "Concepts",
    question: "ATT&CK groups represent:",
    options: ["Adversary groups or actors", "Software vendors", "Patch schedules", "Network segments"],
    correctAnswer: 0,
    explanation: "Groups are adversary sets like APTs.",
  },
  {
    id: 42,
    topic: "Concepts",
    question: "ATT&CK software entries describe:",
    options: ["Tools and malware used by adversaries", "Only operating systems", "Only vulnerabilities", "Only patches"],
    correctAnswer: 0,
    explanation: "Software entries include tools and malware.",
  },
  {
    id: 43,
    topic: "Concepts",
    question: "ATT&CK is not:",
    options: ["A vulnerability database", "A behavior framework", "A shared taxonomy", "A detection mapping tool"],
    correctAnswer: 0,
    explanation: "ATT&CK focuses on behaviors, not CVEs.",
  },
  {
    id: 44,
    topic: "Concepts",
    question: "ATT&CK technique pages include:",
    options: ["Description, detection, and mitigation ideas", "Only CVE lists", "Only exploit code", "Only patch notes"],
    correctAnswer: 0,
    explanation: "Each technique includes detection and mitigation guidance.",
  },
  {
    id: 45,
    topic: "Concepts",
    question: "ATT&CK is useful for:",
    options: ["Threat hunting hypotheses", "Only policy writing", "Only user training", "Only network design"],
    correctAnswer: 0,
    explanation: "Hunts can be mapped to ATT&CK techniques.",
  },
  {
    id: 46,
    topic: "Concepts",
    question: "A heatmap in Navigator shows:",
    options: ["Coverage or priority by technique", "Disk usage", "CPU temperature", "Patch status"],
    correctAnswer: 0,
    explanation: "Heatmaps visualize coverage or risk.",
  },
  {
    id: 47,
    topic: "Concepts",
    question: "ATT&CK tactics are arranged:",
    options: ["Left to right by attack lifecycle", "Randomly", "Alphabetically only", "By CVSS score"],
    correctAnswer: 0,
    explanation: "The matrix flows across tactics.",
  },
  {
    id: 48,
    topic: "Concepts",
    question: "A detection mapped to ATT&CK should include:",
    options: ["Technique ID and context", "Only a log line", "Only a severity", "Only a ticket ID"],
    correctAnswer: 0,
    explanation: "Technique mapping improves clarity and coverage.",
  },
  {
    id: 49,
    topic: "Concepts",
    question: "ATT&CK can help prioritize:",
    options: ["Detections based on adversary behavior", "Printer queues", "Monitor brightness", "Keyboard layouts"],
    correctAnswer: 0,
    explanation: "Behavior-based prioritization improves defense.",
  },
  {
    id: 50,
    topic: "Concepts",
    question: "A technique can map to multiple tactics because:",
    options: ["The same method can achieve different goals", "Tactics are random", "IDs are reused", "Mitigations are missing"],
    correctAnswer: 0,
    explanation: "Techniques can support multiple objectives.",
  },
  {
    id: 51,
    topic: "Examples",
    question: "Phishing is typically an Initial Access technique because:",
    options: ["It gains entry via social engineering", "It only exfiltrates data", "It only disables logging", "It only scans networks"],
    correctAnswer: 0,
    explanation: "Phishing is a common initial entry method.",
  },
  {
    id: 52,
    topic: "Examples",
    question: "Process injection is often used for:",
    options: ["Defense evasion and privilege escalation", "Data archiving", "Network discovery", "User training"],
    correctAnswer: 0,
    explanation: "Injection hides or elevates malicious code.",
  },
  {
    id: 53,
    topic: "Examples",
    question: "Credential dumping supports which tactic?",
    options: ["Credential Access", "Collection", "Exfiltration", "Impact"],
    correctAnswer: 0,
    explanation: "Credential dumping steals secrets.",
  },
  {
    id: 54,
    topic: "Examples",
    question: "Remote Services is commonly used for:",
    options: ["Lateral Movement", "Reconnaissance", "Impact", "Exfiltration"],
    correctAnswer: 0,
    explanation: "Remote services allow movement between systems.",
  },
  {
    id: 55,
    topic: "Examples",
    question: "Data encryption for impact maps to:",
    options: ["Impact", "Execution", "Discovery", "Collection"],
    correctAnswer: 0,
    explanation: "Encrypting data is an impact technique.",
  },
  {
    id: 56,
    topic: "Examples",
    question: "System Information Discovery maps to:",
    options: ["Discovery", "Execution", "Impact", "Initial Access"],
    correctAnswer: 0,
    explanation: "It gathers system details.",
  },
  {
    id: 57,
    topic: "Examples",
    question: "Ingress Tool Transfer is commonly used for:",
    options: ["Command and Control", "Impact", "Exfiltration", "Reconnaissance"],
    correctAnswer: 0,
    explanation: "It brings tools into the environment.",
  },
  {
    id: 58,
    topic: "Examples",
    question: "Exfiltration Over C2 Channel maps to:",
    options: ["Exfiltration", "Command and Control", "Impact", "Collection"],
    correctAnswer: 0,
    explanation: "It is an exfiltration technique.",
  },
  {
    id: 59,
    topic: "Hunting",
    question: "Threat hunting with ATT&CK means:",
    options: ["Building hypotheses based on techniques", "Only using IOC lists", "Only scanning ports", "Only reviewing patches"],
    correctAnswer: 0,
    explanation: "ATT&CK guides hunt hypotheses.",
  },
  {
    id: 60,
    topic: "Hunting",
    question: "ATT&CK is updated:",
    options: ["Periodically with new techniques and changes", "Never after release", "Daily with CVEs only", "Only by vendors"],
    correctAnswer: 0,
    explanation: "MITRE releases periodic updates.",
  },
  {
    id: 61,
    topic: "Operations",
    question: "ATT&CK can help build:",
    options: ["Detection engineering backlogs", "Only user training", "Only firewall configs", "Only patch schedules"],
    correctAnswer: 0,
    explanation: "Coverage gaps feed detection roadmaps.",
  },
  {
    id: 62,
    topic: "Operations",
    question: "Mapping incidents to ATT&CK helps:",
    options: ["Standardize reporting and lessons learned", "Hide evidence", "Disable logging", "Avoid triage"],
    correctAnswer: 0,
    explanation: "Mapping improves reporting and analysis.",
  },
  {
    id: 63,
    topic: "Operations",
    question: "ATT&CK mitigations can be used to:",
    options: ["Plan security controls by technique", "Assign CVSS scores", "Patch kernels automatically", "Disable alerts"],
    correctAnswer: 0,
    explanation: "Mitigations guide control selection.",
  },
  {
    id: 64,
    topic: "Operations",
    question: "ATT&CK detections provide:",
    options: ["Ideas for monitoring and data sources", "Exploit code", "Passwords", "Patch binaries"],
    correctAnswer: 0,
    explanation: "Detection guidance suggests telemetry sources.",
  },
  {
    id: 65,
    topic: "Operations",
    question: "A technique in ATT&CK can have:",
    options: ["Multiple sub-techniques", "Only one example", "No description", "No IDs"],
    correctAnswer: 0,
    explanation: "Sub-techniques describe specific variants.",
  },
  {
    id: 66,
    topic: "Operations",
    question: "ATT&CK does not replace:",
    options: ["Risk assessment and business context", "Threat hunting", "Detection engineering", "Incident response"],
    correctAnswer: 0,
    explanation: "You still need business context and risk analysis.",
  },
  {
    id: 67,
    topic: "Operations",
    question: "ATT&CK is vendor neutral because:",
    options: ["It describes behaviors, not products", "It only lists tools", "It only lists CVEs", "It is proprietary"],
    correctAnswer: 0,
    explanation: "It is a behavior-based taxonomy.",
  },
  {
    id: 68,
    topic: "Operations",
    question: "ATT&CK should be used with:",
    options: ["Local telemetry and environment context", "Only threat feeds", "Only CVSS scores", "Only vulnerability scanners"],
    correctAnswer: 0,
    explanation: "Local context is critical for prioritization.",
  },
  {
    id: 69,
    topic: "Operations",
    question: "Technique coverage does not mean:",
    options: ["Guaranteed prevention", "Visibility into activity", "A detection exists", "A mapping was done"],
    correctAnswer: 0,
    explanation: "Coverage does not guarantee prevention or blocking.",
  },
  {
    id: 70,
    topic: "Operations",
    question: "The best way to validate ATT&CK coverage is:",
    options: ["Test detections with simulations", "Assume mappings are correct", "Disable alerting", "Remove telemetry"],
    correctAnswer: 0,
    explanation: "Testing confirms detections are effective.",
  },
  {
    id: 71,
    topic: "Concepts",
    question: "ATT&CK complements the Cyber Kill Chain by:",
    options: ["Providing detailed technique-level behaviors", "Replacing all tactics", "Focusing only on malware", "Ignoring defender actions"],
    correctAnswer: 0,
    explanation: "ATT&CK adds granular technique detail.",
  },
  {
    id: 72,
    topic: "Concepts",
    question: "The Enterprise matrix includes:",
    options: ["Windows, macOS, Linux, and cloud behaviors", "Only mobile apps", "Only ICS devices", "Only web apps"],
    correctAnswer: 0,
    explanation: "Enterprise covers common enterprise platforms.",
  },
  {
    id: 73,
    topic: "Concepts",
    question: "MITRE ATT&CK is maintained by:",
    options: ["MITRE Corporation", "OWASP", "NIST only", "Vendor consortium"],
    correctAnswer: 0,
    explanation: "MITRE maintains the ATT&CK knowledge base.",
  },
  {
    id: 74,
    topic: "Concepts",
    question: "ATT&CK does not directly provide:",
    options: ["Exploit code", "Behavior descriptions", "Technique IDs", "Mitigation ideas"],
    correctAnswer: 0,
    explanation: "ATT&CK documents behaviors, not exploit code.",
  },
  {
    id: 75,
    topic: "Summary",
    question: "The main value of ATT&CK is:",
    options: ["A shared language for adversary behavior", "A patch management system", "A vulnerability scanner", "A firewall appliance"],
    correctAnswer: 0,
    explanation: "ATT&CK provides a common behavior taxonomy.",
  },
];

export default function MitreAttackPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const accent = ACCENT_COLOR;
  const [searchQuery, setSearchQuery] = useState("");
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");
  const [expandedTactics, setExpandedTactics] = useState<string[]>(["TA0043"]);

  // Icons for each tactic
  const tacticIcons: Record<string, React.ReactNode> = {
    "TA0043": <GpsFixedIcon />,        // Reconnaissance
    "TA0042": <BuildIcon />,           // Resource Development
    "TA0001": <MeetingRoomIcon />,     // Initial Access
    "TA0002": <FlashOnIcon />,         // Execution
    "TA0003": <PushPinIcon />,         // Persistence
    "TA0004": <TrendingUpIcon />,      // Privilege Escalation
    "TA0005": <VisibilityOffIcon />,   // Defense Evasion
    "TA0006": <VpnKeyIcon />,          // Credential Access
    "TA0007": <ExploreIcon />,         // Discovery
    "TA0008": <SwapHorizIcon />,       // Lateral Movement
    "TA0009": <InventoryIcon />,       // Collection
    "TA0011": <SettingsRemoteIcon />,  // Command and Control
    "TA0010": <CloudUploadIcon />,     // Exfiltration
    "TA0040": <WarningIcon />,         // Impact
  };

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "beginner-guide", label: "Beginner Guide", icon: <BookIcon /> },
    { id: "operationalizing", label: "Operationalizing", icon: <SettingsIcon /> },
    { id: "tactics-matrix", label: "ATT&CK Matrix", icon: <ListAltIcon />, isHeader: true },
    // All 14 tactics
    ...tactics.map((tactic, index) => ({
      id: `tactic-${tactic.id}`,
      label: `${index + 1}. ${tactic.shortName}`,
      icon: tacticIcons[tactic.id] || <ListAltIcon />,
      indent: true,
      color: tactic.color,
    })),
    { id: "telemetry", label: "Telemetry & Metrics", icon: <DataUsageIcon /> },
    { id: "misconceptions", label: "Misconceptions", icon: <WarningIcon /> },
    { id: "resources", label: "Resources", icon: <LinkIcon /> },
    { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
  ];

  const handleTacticToggle = (tacticId: string) => {
    setExpandedTactics((prev) =>
      prev.includes(tacticId) ? prev.filter((id) => id !== tacticId) : [...prev, tacticId]
    );
  };

  const expandAllTactics = () => setExpandedTactics(tactics.map((t) => t.id));
  const collapseAllTactics = () => setExpandedTactics([]);

  const filteredTactics = useMemo(() => {
    if (!searchQuery.trim()) return tactics;
    const query = searchQuery.toLowerCase();
    return tactics.map((tactic) => ({
      ...tactic,
      techniques: tactic.techniques.filter(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          t.id.toLowerCase().includes(query) ||
          t.description.toLowerCase().includes(query)
      ),
    })).filter((tactic) => tactic.techniques.length > 0 || tactic.name.toLowerCase().includes(query));
  }, [searchQuery]);

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const offset = 80;
      const elementPosition = element.getBoundingClientRect().top;
      const offsetPosition = elementPosition + window.pageYOffset - offset;
      window.scrollTo({ top: offsetPosition, behavior: "smooth" });
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = sections[0];
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

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const progressPercent =
    ((sectionNavItems.findIndex((item) => item.id === activeSection) + 1) /
      sectionNavItems.length) *
    100;

  const totalTechniques = tactics.reduce((acc, t) => acc + t.techniques.length, 0);

  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        position: "sticky",
        top: 80,
        width: 220,
        flexShrink: 0,
        borderRadius: 3,
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        backdropFilter: "blur(10px)",
        overflow: "hidden",
        display: { xs: "none", md: "block" },
      }}
    >
      <Box sx={{ p: 2, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, textTransform: "uppercase", letterSpacing: 1 }}>
          On This Page
        </Typography>
        <LinearProgress
          variant="determinate"
          value={progressPercent}
          sx={{
            mt: 1,
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(accent, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: accent },
          }}
        />
      </Box>
      <List dense sx={{ py: 1, maxHeight: "calc(100vh - 280px)", overflowY: "auto" }}>
        {sectionNavItems.map((item: any) => (
          <ListItemButton
            key={item.id}
            onClick={() => {
              scrollToSection(item.id);
              // If clicking a tactic, expand it
              if (item.id.startsWith("tactic-")) {
                const tacticId = item.id.replace("tactic-", "");
                if (!expandedTactics.includes(tacticId)) {
                  setExpandedTactics((prev) => [...prev, tacticId]);
                }
              }
            }}
            selected={activeSection === item.id}
            sx={{
              py: item.indent ? 0.5 : 0.75,
              px: 2,
              pl: item.indent ? 3 : 2,
              borderLeft: `3px solid ${activeSection === item.id ? (item.color || accent) : "transparent"}`,
              bgcolor: activeSection === item.id ? alpha(item.color || accent, 0.08) : "transparent",
              "&:hover": { bgcolor: alpha(item.color || accent, 0.05) },
            }}
          >
            <ListItemIcon sx={{ minWidth: item.indent ? 24 : 32, color: activeSection === item.id ? (item.color || accent) : "text.secondary", "& .MuiSvgIcon-root": { fontSize: item.indent ? "1rem" : "1.25rem" } }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                variant: "body2",
                fontWeight: activeSection === item.id ? 600 : (item.isHeader ? 600 : 400),
                color: activeSection === item.id ? (item.color || accent) : "text.secondary",
                fontSize: item.indent ? "0.7rem" : "0.8rem",
                noWrap: true,
              }}
            />
          </ListItemButton>
        ))}
      </List>
      <Box sx={{ p: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
        <Button
          component={RouterLink}
          to="/learn"
          startIcon={<ArrowBackIcon />}
          size="small"
          fullWidth
          sx={{ justifyContent: "flex-start", color: "text.secondary" }}
        >
          Learning Hub
        </Button>
      </Box>
    </Paper>
  );

  const pageContext = `MITRE ATT&CK Framework Guide - Comprehensive coverage of adversary tactics, techniques, and procedures (TTPs). Covers all MITRE ATT&CK tactics: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, and Impact. Each tactic includes specific techniques with IDs, descriptions, and real-world examples used by threat actors. Essential knowledge for threat intelligence, red team operations, and security analysis.`;

  return (
    <LearnPageLayout pageTitle="MITRE ATT&CK Framework" pageContext={pageContext}>
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
              zIndex: 1000,
              bgcolor: accent,
              color: "white",
              "&:hover": { bgcolor: alpha(accent, 0.9) },
            }}
          >
            <ListAltIcon />
          </Fab>
          <Fab
            size="small"
            onClick={scrollToTop}
            sx={{
              position: "fixed",
              bottom: 24,
              right: 16,
              zIndex: 1000,
              bgcolor: alpha(theme.palette.background.paper, 0.9),
              border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
              "&:hover": { bgcolor: theme.palette.background.paper },
            }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        </>
      )}

      {/* Mobile Drawer */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: 280,
            bgcolor: theme.palette.background.default,
            p: 2,
          },
        }}
      >
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
            Navigate
          </Typography>
          <Tooltip title="Close">
            <Fab size="small" onClick={() => setNavDrawerOpen(false)} sx={{ boxShadow: 0 }}>
              <CloseIcon />
            </Fab>
          </Tooltip>
        </Box>
        <List dense sx={{ maxHeight: "60vh", overflowY: "auto" }}>
          {sectionNavItems.map((item: any) => (
            <ListItemButton
              key={item.id}
              onClick={() => {
                scrollToSection(item.id);
                // If clicking a tactic, expand it
                if (item.id.startsWith("tactic-")) {
                  const tacticId = item.id.replace("tactic-", "");
                  if (!expandedTactics.includes(tacticId)) {
                    setExpandedTactics((prev) => [...prev, tacticId]);
                  }
                }
              }}
              selected={activeSection === item.id}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                ml: item.indent ? 2 : 0,
                bgcolor: activeSection === item.id ? alpha(item.color || accent, 0.1) : "transparent",
              }}
            >
              <ListItemIcon sx={{ minWidth: item.indent ? 28 : 36, color: activeSection === item.id ? (item.color || accent) : "text.secondary", "& .MuiSvgIcon-root": { fontSize: item.indent ? "1rem" : "1.25rem" } }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                primaryTypographyProps={{
                  fontWeight: activeSection === item.id ? 600 : (item.isHeader ? 600 : 400),
                  color: activeSection === item.id ? (item.color || accent) : "text.primary",
                  fontSize: item.indent ? "0.85rem" : "1rem",
                }}
              />
            </ListItemButton>
          ))}
        </List>
        <Box sx={{ mt: 2, display: "flex", gap: 1 }}>
          <Button size="small" variant="outlined" onClick={scrollToTop} startIcon={<KeyboardArrowUpIcon />}>
            Top
          </Button>
          <Button
            size="small"
            variant="contained"
            onClick={() => scrollToSection("quiz-section")}
            startIcon={<QuizIcon />}
            sx={{ bgcolor: accent, "&:hover": { bgcolor: alpha(accent, 0.9) } }}
          >
            Quiz
          </Button>
        </Box>
        <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Button
            component={RouterLink}
            to="/learn"
            startIcon={<ArrowBackIcon />}
            fullWidth
            variant="outlined"
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box
        sx={{
          display: "flex",
          gap: 3,
          maxWidth: 1200,
          mx: "auto",
          px: { xs: 2, md: 3 },
          py: 4,
        }}
      >
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Button */}
          <Chip
            component={RouterLink}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

          {/* Header */}
          <Box id="intro" sx={{ mb: 5 }}>
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
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
              If you are a beginner, think of ATT&CK as a dictionary of attacker behaviors. The left side of the matrix shows the goals (tactics) and each column is a collection of ways to reach that goal (techniques). Technique IDs like T1059 or T1566 are stable labels you can use in notes, incident reports, or detection rules. You do not need to memorize them to benefit; just use them as references when you look up details.
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
              ATT&CK is not a checklist of vulnerabilities, and it does not replace risk assessment. It is a shared language so that analysts, engineers, and leaders can talk about the same behaviors. When you see an alert or a red team report, mapping it to ATT&CK helps you compare it with past incidents and understand which gaps remain.
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

      {/* Beginner Guide */}
      <Paper id="beginner-guide" sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha(theme.palette.background.paper, 0.6), border: `1px solid ${alpha(theme.palette.divider, 0.12)}` }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Beginner Guide to ATT&CK
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          Start with tactics. A tactic is the adversary's objective at that point in the intrusion, such as "Initial Access" or "Credential Access." Once you understand the objective, look at the techniques underneath it. Techniques are the specific behaviors that achieve the objective, such as phishing, exploiting a public-facing app, or dumping credentials from memory. In practice, different tools can perform the same technique, which is why the framework focuses on behavior rather than product names.
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          Next, pick a familiar environment. For example, if you know Windows, focus on techniques that mention PowerShell, scheduled tasks, or registry changes. If you work in cloud environments, look for techniques that mention cloud accounts, tokens, or API abuse. This approach makes the matrix feel smaller and more relevant, which is helpful when you are starting out.
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9 }}>
          Finally, use ATT&CK as a study aid. When you read a breach report, identify which tactics and techniques were involved. Over time, you will start to see patterns and recognize common attacker playbooks. That is the practical value of ATT&CK: it turns isolated incidents into a repeatable learning loop.
        </Typography>
      </Paper>

      {/* Operational Guidance */}
      <Paper
        id="operationalizing"
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#1d4ed8", 0.05)}, ${alpha("#f59e0b", 0.05)})`,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Operationalizing ATT&CK
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          This section translates the framework into day to day security work. A common beginner mistake is to read ATT&CK like a static list. In practice, teams use it to guide prioritization, build detection backlogs, and structure incident reports. The goal is not to cover everything at once, but to make steady, measurable progress.
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          Think of ATT&CK as a bridge between threats and controls. When you map a technique to a detection or mitigation, you are making a simple promise: if that behavior happens, you will see it, stop it, or at least investigate it quickly. Over time, these promises add up to stronger security posture.
        </Typography>
        <Grid container spacing={3}>
          {operationalGuides.map((guide) => (
            <Grid item xs={12} md={6} key={guide.title}>
              <Paper sx={{ p: 3, borderRadius: 2, border: `1px solid ${alpha(guide.color, 0.2)}`, bgcolor: alpha(guide.color, 0.04) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: guide.color, mb: 1.5 }}>
                  {guide.title}
                </Typography>
                {guide.points.map((point) => (
                  <Box key={point} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1.2 }}>
                    <Box sx={{ width: 6, height: 6, mt: 0.9, borderRadius: "50%", bgcolor: guide.color }} />
                    <Typography variant="body2" color="text.secondary">
                      {point}
                    </Typography>
                  </Box>
                ))}
              </Paper>
            </Grid>
          ))}
        </Grid>
        <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
          <Typography variant="body2">
            <strong>Tip:</strong> Use ATT&CK as a behavior taxonomy, not a compliance checklist. Prioritize based on your environment and threat model.
          </Typography>
        </Alert>
      </Paper>

      {/* ATT&CK Matrix - All 14 Tactics */}
      <Box id="tactics-matrix" sx={{ mb: 5 }}>
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#f59e0b", 0.05)})` }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            🎯 The ATT&CK Matrix
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
            Below you'll find all <strong>14 tactics</strong> and their <strong>{totalTechniques} techniques</strong> organized by attack lifecycle. 
            Each tactic represents an adversary goal, and techniques are the specific methods used to achieve that goal. 
            Click on any tactic to expand and explore its techniques. Use the search to filter across all tactics and techniques.
          </Typography>
          
          {/* Search and Controls */}
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, alignItems: "center", mb: 3 }}>
            <TextField
              size="small"
              placeholder="Search all techniques..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon color="action" />
                  </InputAdornment>
                ),
              }}
              sx={{ minWidth: 300, flex: 1, maxWidth: 400 }}
            />
            <Box sx={{ display: "flex", gap: 1 }}>
              <Button size="small" variant="outlined" onClick={expandAllTactics}>
                Expand All
              </Button>
              <Button size="small" variant="outlined" onClick={collapseAllTactics}>
                Collapse All
              </Button>
            </Box>
          </Box>

          {/* Stats Bar */}
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mb: 2 }}>
            <Chip label={`${filteredTactics.length} Tactics`} sx={{ bgcolor: alpha("#dc2626", 0.1), color: "#dc2626", fontWeight: 600 }} />
            <Chip label={`${filteredTactics.reduce((acc, t) => acc + t.techniques.length, 0)} Techniques`} variant="outlined" />
            {searchQuery && <Chip label={`Searching: "${searchQuery}"`} onDelete={() => setSearchQuery("")} size="small" />}
          </Box>
        </Paper>

        {/* All Tactics as Accordions */}
        {filteredTactics.length === 0 ? (
          <Alert severity="info" sx={{ borderRadius: 2 }}>
            No tactics or techniques match your search. Try a different keyword.
          </Alert>
        ) : (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {filteredTactics.map((tactic, index) => (
              <Accordion
                key={tactic.id}
                id={`tactic-${tactic.id}`}
                expanded={expandedTactics.includes(tactic.id)}
                onChange={() => handleTacticToggle(tactic.id)}
                sx={{
                  borderRadius: "12px !important",
                  overflow: "hidden",
                  border: `2px solid ${alpha(tactic.color, 0.2)}`,
                  "&:before": { display: "none" },
                  bgcolor: alpha(theme.palette.background.paper, 0.8),
                  "&.Mui-expanded": { 
                    border: `2px solid ${tactic.color}`,
                    boxShadow: `0 4px 20px ${alpha(tactic.color, 0.15)}` 
                  },
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon sx={{ color: tactic.color }} />}
                  sx={{
                    bgcolor: alpha(tactic.color, 0.05),
                    "&:hover": { bgcolor: alpha(tactic.color, 0.1) },
                    minHeight: 72,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", pr: 2 }}>
                    <Typography variant="h4" sx={{ minWidth: 50 }}>{tactic.icon}</Typography>
                    <Box sx={{ flex: 1 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, flexWrap: "wrap" }}>
                        <Typography variant="h6" sx={{ fontWeight: 700 }}>
                          {index + 1}. {tactic.name}
                        </Typography>
                        <Chip 
                          label={tactic.id} 
                          size="small" 
                          sx={{ 
                            bgcolor: alpha(tactic.color, 0.15), 
                            color: tactic.color, 
                            fontWeight: 600,
                            fontSize: "0.7rem" 
                          }} 
                        />
                        <Chip
                          label={`${tactic.techniques.length} techniques`}
                          size="small"
                          variant="outlined"
                          sx={{ borderColor: alpha(tactic.color, 0.3), color: tactic.color, fontSize: "0.7rem" }}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, display: { xs: "none", sm: "block" } }}>
                        {tactic.description}
                      </Typography>
                    </Box>
                  </Box>
                </AccordionSummary>
                <AccordionDetails sx={{ p: 3, bgcolor: alpha(tactic.color, 0.02) }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 3, display: { xs: "block", sm: "none" } }}>
                    {tactic.description}
                  </Typography>
                  
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: tactic.color }}>
                      Techniques
                    </Typography>
                    <Link
                      href={`https://attack.mitre.org/tactics/${tactic.id}/`}
                      target="_blank"
                      rel="noopener"
                      sx={{ display: "inline-flex", alignItems: "center", gap: 0.5, fontSize: "0.875rem" }}
                    >
                      View on MITRE <LaunchIcon fontSize="small" />
                    </Link>
                  </Box>

                  <Grid container spacing={2}>
                    {tactic.techniques.map((technique) => (
                      <Grid item xs={12} md={6} lg={4} key={technique.id}>
                        <Paper
                          sx={{
                            p: 2,
                            height: "100%",
                            border: `1px solid ${alpha(tactic.color, 0.15)}`,
                            borderRadius: 2,
                            transition: "all 0.2s",
                            "&:hover": { 
                              borderColor: tactic.color, 
                              bgcolor: alpha(tactic.color, 0.05),
                              transform: "translateY(-2px)",
                              boxShadow: `0 4px 12px ${alpha(tactic.color, 0.1)}`
                            },
                          }}
                        >
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, fontSize: "0.9rem" }}>
                              {technique.name}
                            </Typography>
                            <Link
                              href={`https://attack.mitre.org/techniques/${technique.id}/`}
                              target="_blank"
                              rel="noopener"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <Chip
                                label={technique.id}
                                size="small"
                                clickable
                                sx={{ 
                                  fontSize: "0.65rem", 
                                  height: 22,
                                  bgcolor: alpha(tactic.color, 0.1), 
                                  color: tactic.color,
                                  "&:hover": { bgcolor: alpha(tactic.color, 0.2) }
                                }}
                              />
                            </Link>
                          </Box>
                          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.5, fontSize: "0.85rem" }}>
                            {technique.description}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>
        )}
      </Box>

      {/* Telemetry and Measurement */}
      <Paper id="telemetry" sx={{ p: 4, mb: 5, borderRadius: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Telemetry, Validation, and Metrics
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          ATT&CK becomes practical when you connect techniques to data. Telemetry tells you what signals you actually have, validation tells you whether your detections work, and metrics tell you whether coverage is improving. Beginners often focus only on detections, but without good data and validation those detections can be misleading.
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          Use these panels as a starting point. If you do not have the data source for a technique, it is difficult to detect it reliably. If you do not test detections, you do not know if they work. If you do not measure progress, you cannot prioritize what to fix next.
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}`, bgcolor: alpha("#3b82f6", 0.04), height: "100%" }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                Common Data Sources
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {telemetrySources.map((source) => (
                  <Chip key={source} label={source} size="small" sx={{ fontSize: "0.75rem", bgcolor: alpha("#3b82f6", 0.1), color: "#3b82f6" }} />
                ))}
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}`, bgcolor: alpha("#10b981", 0.04), height: "100%" }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2 }}>
                Validation Checklist
              </Typography>
              {validationSteps.map((step) => (
                <Box key={step} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1.2 }}>
                  <Box sx={{ width: 6, height: 6, mt: 0.9, borderRadius: "50%", bgcolor: "#10b981" }} />
                  <Typography variant="body2" color="text.secondary">
                    {step}
                  </Typography>
                </Box>
              ))}
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}`, bgcolor: alpha("#f59e0b", 0.04), height: "100%" }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>
                Reporting and Metrics
              </Typography>
              {reportingMetrics.map((metric) => (
                <Box key={metric} sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1.2 }}>
                  <Box sx={{ width: 6, height: 6, mt: 0.9, borderRadius: "50%", bgcolor: "#f59e0b" }} />
                  <Typography variant="body2" color="text.secondary">
                    {metric}
                  </Typography>
                </Box>
              ))}
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      {/* Common Misconceptions */}
      <Paper id="misconceptions" sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.04), border: `1px solid ${alpha("#f59e0b", 0.12)}` }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Common Misconceptions
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9, mb: 3 }}>
          A frequent misunderstanding is that ATT&CK is only for red teams. In reality, defenders use it to build detections, design response playbooks, and communicate incidents. Another misconception is that mapping a control to a technique means you are fully protected. A mapping is a hypothesis; you still need validation and monitoring to confirm it.
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.9 }}>
          Beginners also sometimes treat the matrix as a checklist to complete. This usually leads to shallow coverage. A better approach is depth over breadth: choose a few high risk techniques, build strong telemetry and detections for them, and expand steadily as your program matures.
        </Typography>
      </Paper>

      {/* Resources */}
      <Paper id="resources" sx={{ p: 4, borderRadius: 3 }}>
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

      <Paper
        id="quiz-section"
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
        }}
      >
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
          Knowledge Check
        </Typography>
        <QuizSection
          questions={quizQuestions}
          accentColor={QUIZ_ACCENT_COLOR}
          title="MITRE ATT&CK Framework Knowledge Check"
          description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
          questionsPerQuiz={QUIZ_QUESTION_COUNT}
        />
      </Paper>

      {/* Related Learning Topics */}
      <Paper sx={{ p: 4, mt: 5, borderRadius: 3, bgcolor: alpha(theme.palette.background.paper, 0.6), border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          📚 Related Learning Topics
        </Typography>
        <Grid container spacing={2}>
          {[
            { title: "Cyber Kill Chain", path: "/learn/kill-chain", desc: "Linear attack model that complements ATT&CK", icon: "🎯" },
            { title: "Threat Hunting", path: "/learn/threat-hunting", desc: "Proactive detection using ATT&CK hypotheses", icon: "🔍" },
            { title: "Incident Response", path: "/learn/incident-response", desc: "Response procedures mapped to ATT&CK", icon: "🚨" },
            { title: "Malware Analysis", path: "/learn/malware-analysis", desc: "Analyze samples and map to techniques", icon: "🦠" },
          ].map((topic) => (
            <Grid item xs={12} sm={6} key={topic.path}>
              <Paper
                component={RouterLink}
                to={topic.path}
                sx={{
                  p: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 2,
                  textDecoration: "none",
                  border: `1px solid ${alpha(accent, 0.15)}`,
                  borderRadius: 2,
                  transition: "all 0.2s",
                  "&:hover": { borderColor: accent, bgcolor: alpha(accent, 0.05), transform: "translateX(4px)" },
                }}
              >
                <Typography variant="h5">{topic.icon}</Typography>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "text.primary" }}>
                    {topic.title}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {topic.desc}
                  </Typography>
                </Box>
              </Paper>
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
          sx={{ borderColor: accent, color: accent }}
        >
          Back to Learning Hub
        </Button>
      </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
