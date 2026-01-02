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
  Button,
} from "@mui/material";
import { useState, useMemo } from "react";
import { Link as RouterLink, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import QuizIcon from "@mui/icons-material/Quiz";

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

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#3b82f6";
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
