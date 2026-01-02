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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  Button,
} from "@mui/material";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import BuildIcon from "@mui/icons-material/Build";
import LocalShippingIcon from "@mui/icons-material/LocalShipping";
import BugReportIcon from "@mui/icons-material/BugReport";
import InstallDesktopIcon from "@mui/icons-material/InstallDesktop";
import SettingsRemoteIcon from "@mui/icons-material/SettingsRemote";
import FlagIcon from "@mui/icons-material/Flag";
import ShieldIcon from "@mui/icons-material/Shield";
import WarningIcon from "@mui/icons-material/Warning";
import QuizIcon from "@mui/icons-material/Quiz";

interface KillChainPhase {
  id: number;
  name: string;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  attackerActions: string[];
  defenderActions: string[];
  tools: string[];
  indicators: string[];
  realWorldExample: string;
}

const killChainPhases: KillChainPhase[] = [
  {
    id: 1,
    name: "Reconnaissance",
    subtitle: "Target Research & Information Gathering",
    icon: <GpsFixedIcon />,
    color: "#6366f1",
    description:
      "The attacker identifies and researches targets. They gather information about the organization, employees, technology stack, and potential vulnerabilities without directly interacting with target systems.",
    attackerActions: [
      "Harvest email addresses from websites, social media, job postings",
      "Identify employees on LinkedIn, their roles and technologies used",
      "Enumerate subdomains, IP ranges, and exposed services",
      "Research technology stack via job postings, Wappalyzer, BuiltWith",
      "Gather leaked credentials from breach databases",
      "Map organizational structure and identify high-value targets",
    ],
    defenderActions: [
      "Monitor for domain enumeration in DNS logs",
      "Limit public exposure of employee information",
      "Review and sanitize job postings for technical details",
      "Implement brand monitoring for credential leaks",
      "Use honeypots to detect reconnaissance activity",
      "Conduct red team exercises to identify exposed data",
    ],
    tools: ["Maltego", "Shodan", "theHarvester", "Recon-ng", "SpiderFoot", "OSINT Framework", "hunter.io"],
    indicators: ["Unusual DNS queries", "Port scanning from single source", "Social engineering attempts", "Job posting scraping"],
    realWorldExample: "In the 2020 SolarWinds attack, threat actors spent months researching targets and understanding the supply chain before proceeding.",
  },
  {
    id: 2,
    name: "Weaponization",
    subtitle: "Malware Development & Payload Creation",
    icon: <BuildIcon />,
    color: "#8b5cf6",
    description:
      "The attacker creates or acquires tools to exploit identified vulnerabilities. This includes developing malware, creating exploit payloads, and setting up attack infrastructure.",
    attackerActions: [
      "Develop custom malware tailored to target environment",
      "Modify existing exploits to bypass specific defenses",
      "Create weaponized documents (macro-enabled Office files)",
      "Set up command and control (C2) infrastructure",
      "Acquire or develop zero-day exploits",
      "Create phishing pages mimicking legitimate services",
      "Generate obfuscated payloads to evade detection",
    ],
    defenderActions: [
      "Share threat intelligence with industry peers (ISACs)",
      "Implement application allowlisting",
      "Use sandboxing for unknown executables",
      "Block macro execution in Office documents",
      "Monitor dark web for threats targeting your org",
      "Patch vulnerabilities before exploits are developed",
    ],
    tools: ["Metasploit", "Cobalt Strike", "Veil", "msfvenom", "Empire", "Custom malware frameworks"],
    indicators: ["This phase occurs outside your network - limited visibility"],
    realWorldExample: "APT groups often spend months developing custom implants. Lazarus Group developed ELECTRICFISH tunneling tool specifically for financial institutions.",
  },
  {
    id: 3,
    name: "Delivery",
    subtitle: "Transmission of Malicious Payload",
    icon: <LocalShippingIcon />,
    color: "#a855f7",
    description:
      "The attacker transmits the weaponized payload to the target. Common vectors include phishing emails, compromised websites, USB drops, and supply chain compromises.",
    attackerActions: [
      "Send spear-phishing emails with malicious attachments",
      "Compromise legitimate websites to host exploit kits",
      "Deploy watering hole attacks on sites victims visit",
      "Distribute infected USB drives near target facilities",
      "Exploit public-facing applications directly",
      "Compromise third-party vendors in supply chain",
      "Use social engineering via phone or in-person",
    ],
    defenderActions: [
      "Deploy email security with attachment sandboxing",
      "Implement web filtering and secure web gateways",
      "Train employees on phishing identification",
      "Disable USB ports or implement device control",
      "Patch public-facing applications immediately",
      "Implement vendor security assessments",
      "Use DMARC, DKIM, SPF for email authentication",
    ],
    tools: ["GoPhish", "King Phisher", "SET (Social Engineering Toolkit)", "Evilginx2", "BeEF"],
    indicators: ["Phishing emails detected", "Malicious attachments blocked", "Suspicious downloads", "Drive-by compromise attempts"],
    realWorldExample: "The 2017 NotPetya attack used a compromised Ukrainian accounting software update as the delivery mechanism, affecting companies globally.",
  },
  {
    id: 4,
    name: "Exploitation",
    subtitle: "Vulnerability Exploitation & Code Execution",
    icon: <BugReportIcon />,
    color: "#ec4899",
    description:
      "The attacker exploits a vulnerability to execute malicious code on the target system. This could be a software vulnerability, misconfiguration, or user action (clicking a link, enabling macros).",
    attackerActions: [
      "Execute exploit code against vulnerable software",
      "Leverage user interaction (clicking links, enabling macros)",
      "Exploit browser vulnerabilities for drive-by downloads",
      "Use credential stuffing or password spraying",
      "Bypass authentication mechanisms",
      "Exploit misconfigurations in cloud services",
      "Chain multiple vulnerabilities for greater impact",
    ],
    defenderActions: [
      "Maintain aggressive patch management program",
      "Implement exploit prevention (DEP, ASLR, CFG)",
      "Use endpoint detection and response (EDR)",
      "Deploy application-level firewalls (WAF)",
      "Enforce MFA on all accounts",
      "Regular vulnerability scanning and remediation",
      "Implement least privilege access controls",
    ],
    tools: ["Metasploit", "Burp Suite", "sqlmap", "CrackMapExec", "Impacket", "BloodHound"],
    indicators: ["Exploit attempts in logs", "Unexpected process execution", "Failed authentication spikes", "Vulnerability scanner activity"],
    realWorldExample: "The Equifax breach (2017) exploited CVE-2017-5638, an Apache Struts vulnerability that was 2 months old with a patch available.",
  },
  {
    id: 5,
    name: "Installation",
    subtitle: "Persistence Establishment & Backdoor Deployment",
    icon: <InstallDesktopIcon />,
    color: "#f43f5e",
    description:
      "The attacker installs persistent access mechanisms to maintain access even after reboots or password changes. This includes backdoors, RATs, and privilege escalation.",
    attackerActions: [
      "Install remote access trojans (RATs)",
      "Create scheduled tasks for persistence",
      "Modify registry run keys",
      "Deploy web shells on compromised servers",
      "Create rogue admin accounts",
      "Install rootkits to hide presence",
      "Establish multiple persistence mechanisms",
      "Escalate privileges to SYSTEM/root",
    ],
    defenderActions: [
      "Monitor for unauthorized software installation",
      "Audit scheduled tasks and startup items",
      "Implement application allowlisting",
      "Monitor registry modifications",
      "Audit user account creation",
      "Use file integrity monitoring",
      "Implement privileged access management",
      "Regular system baselining and comparison",
    ],
    tools: ["Mimikatz", "PowerSploit", "SharPersist", "PoshC2", "DVTA", "Web shells (China Chopper, WSO)"],
    indicators: ["New admin accounts", "Unexpected scheduled tasks", "Modified registry keys", "New services installed", "Web shells detected"],
    realWorldExample: "APT29 (Cozy Bear) uses multiple persistence mechanisms including scheduled tasks, WMI subscriptions, and startup folder shortcuts.",
  },
  {
    id: 6,
    name: "Command & Control",
    subtitle: "Remote Control & Communication Channel",
    icon: <SettingsRemoteIcon />,
    color: "#ef4444",
    description:
      "The attacker establishes a communication channel to remotely control compromised systems. C2 channels are often encrypted and designed to blend with normal traffic.",
    attackerActions: [
      "Establish encrypted C2 channel over HTTPS",
      "Use DNS tunneling for covert communication",
      "Leverage legitimate services (Slack, Teams, GitHub)",
      "Implement domain fronting to hide C2 traffic",
      "Use fast-flux DNS to evade blocking",
      "Deploy peer-to-peer C2 networks",
      "Schedule check-ins during business hours to blend in",
    ],
    defenderActions: [
      "Monitor outbound traffic patterns and anomalies",
      "Implement DNS monitoring and filtering",
      "Use SSL/TLS inspection for encrypted traffic",
      "Block known C2 infrastructure (threat intel feeds)",
      "Deploy network detection and response (NDR)",
      "Implement egress filtering",
      "Monitor for beaconing behavior patterns",
    ],
    tools: ["Cobalt Strike", "Covenant", "PoshC2", "Mythic", "Sliver", "DNS over HTTPS tunneling"],
    indicators: ["Beaconing traffic patterns", "Unusual DNS queries", "Traffic to newly registered domains", "Long-duration connections", "Encrypted traffic to unusual destinations"],
    realWorldExample: "Sunburst malware used multiple legitimate domains and cloud services for C2, making detection extremely difficult.",
  },
  {
    id: 7,
    name: "Actions on Objectives",
    subtitle: "Mission Execution & Goal Achievement",
    icon: <FlagIcon />,
    color: "#dc2626",
    description:
      "The attacker achieves their ultimate goal, whether it's data exfiltration, destruction, ransom, or espionage. This is the final stage where damage occurs.",
    attackerActions: [
      "Exfiltrate sensitive data (IP, PII, credentials)",
      "Deploy ransomware for extortion",
      "Manipulate or destroy data",
      "Move laterally to additional systems",
      "Establish long-term persistent access",
      "Use access for cryptocurrency mining",
      "Sell access to other threat actors",
      "Conduct espionage or surveillance",
    ],
    defenderActions: [
      "Implement data loss prevention (DLP)",
      "Monitor for large data transfers",
      "Segment networks to limit lateral movement",
      "Maintain offline backups for ransomware recovery",
      "Implement zero trust architecture",
      "Monitor database queries for anomalies",
      "Deploy deception technologies (honeypots)",
      "Have incident response plan ready",
    ],
    tools: ["Rclone", "MEGAsync", "7-Zip for compression", "Custom exfil tools", "Ransomware variants (LockBit, BlackCat)"],
    indicators: ["Large data transfers", "Unusual database queries", "Access to sensitive file shares", "Encryption activity", "Ransom notes"],
    realWorldExample: "Colonial Pipeline (2021) - DarkSide ransomware encrypted systems after exfiltrating 100GB of data, leading to fuel shortages.",
  },
];

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#f59e0b";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "The Cyber Kill Chain is a framework for:",
    options: ["Describing stages of a cyberattack", "Encrypting data at rest", "Replacing firewalls", "Managing patch cycles"],
    correctAnswer: 0,
    explanation: "It outlines the phases of a targeted attack.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The Kill Chain was popularized by:",
    options: ["Lockheed Martin", "OWASP", "NIST", "CIS"],
    correctAnswer: 0,
    explanation: "The model is known as the Lockheed Martin Kill Chain.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "The Kill Chain includes how many phases?",
    options: ["7", "5", "6", "9"],
    correctAnswer: 0,
    explanation: "The model defines seven phases.",
  },
  {
    id: 4,
    topic: "Phases",
    question: "The first phase is:",
    options: ["Reconnaissance", "Weaponization", "Delivery", "Exploitation"],
    correctAnswer: 0,
    explanation: "Reconnaissance is the initial phase.",
  },
  {
    id: 5,
    topic: "Phases",
    question: "The second phase is:",
    options: ["Weaponization", "Delivery", "Exploitation", "Installation"],
    correctAnswer: 0,
    explanation: "Weaponization follows reconnaissance.",
  },
  {
    id: 6,
    topic: "Phases",
    question: "The third phase is:",
    options: ["Delivery", "Installation", "Actions on Objectives", "Reconnaissance"],
    correctAnswer: 0,
    explanation: "Delivery is when the payload reaches the target.",
  },
  {
    id: 7,
    topic: "Phases",
    question: "The fourth phase is:",
    options: ["Exploitation", "Weaponization", "Delivery", "Actions on Objectives"],
    correctAnswer: 0,
    explanation: "Exploitation triggers the vulnerability or action.",
  },
  {
    id: 8,
    topic: "Phases",
    question: "The fifth phase is:",
    options: ["Installation", "Reconnaissance", "Delivery", "Weaponization"],
    correctAnswer: 0,
    explanation: "Installation places malware or implants.",
  },
  {
    id: 9,
    topic: "Phases",
    question: "The sixth phase is:",
    options: ["Command and Control (C2)", "Exploitation", "Reconnaissance", "Delivery"],
    correctAnswer: 0,
    explanation: "C2 establishes remote control.",
  },
  {
    id: 10,
    topic: "Phases",
    question: "The seventh phase is:",
    options: ["Actions on Objectives", "Weaponization", "Installation", "Exploitation"],
    correctAnswer: 0,
    explanation: "This is where the attacker achieves goals.",
  },
  {
    id: 11,
    topic: "Reconnaissance",
    question: "Reconnaissance focuses on:",
    options: ["Gathering information about the target", "Installing malware", "Exfiltrating data", "Encrypting files"],
    correctAnswer: 0,
    explanation: "Attackers research the target environment.",
  },
  {
    id: 12,
    topic: "Reconnaissance",
    question: "A reconnaissance activity is:",
    options: ["OSINT and scanning", "Dropping a backdoor", "Encrypting backups", "Blocking traffic"],
    correctAnswer: 0,
    explanation: "Recon uses public data and scanning.",
  },
  {
    id: 13,
    topic: "Reconnaissance",
    question: "A common recon indicator is:",
    options: ["Unusual DNS enumeration or port scans", "User login success", "Normal backups", "Patch installs"],
    correctAnswer: 0,
    explanation: "Scanning and enumeration are common signals.",
  },
  {
    id: 14,
    topic: "Weaponization",
    question: "Weaponization involves:",
    options: ["Building the exploit and payload", "Delivering the payload", "Running a phishing test", "Changing firewall rules"],
    correctAnswer: 0,
    explanation: "Attackers prepare the malicious package.",
  },
  {
    id: 15,
    topic: "Weaponization",
    question: "Weaponization is often hard to detect because it:",
    options: ["Happens outside the victim network", "Uses only internal logs", "Requires user clicks", "Always triggers alerts"],
    correctAnswer: 0,
    explanation: "This stage usually occurs off-network.",
  },
  {
    id: 16,
    topic: "Delivery",
    question: "Delivery refers to:",
    options: ["Transmitting the payload to the target", "Executing the payload", "Exfiltrating data", "Installing patches"],
    correctAnswer: 0,
    explanation: "Delivery is how the payload reaches the victim.",
  },
  {
    id: 17,
    topic: "Delivery",
    question: "A common delivery method is:",
    options: ["Spear-phishing email", "Memory scraping", "Credential dumping", "Log tampering"],
    correctAnswer: 0,
    explanation: "Phishing is a common delivery vector.",
  },
  {
    id: 18,
    topic: "Delivery",
    question: "A defensive control for delivery is:",
    options: ["Email filtering and sandboxing", "Disabling backups", "Removing logs", "Ignoring attachments"],
    correctAnswer: 0,
    explanation: "Filtering reduces malicious payloads.",
  },
  {
    id: 19,
    topic: "Exploitation",
    question: "Exploitation is when:",
    options: ["A vulnerability is triggered to run code", "A target is scanned", "A payload is built", "A report is written"],
    correctAnswer: 0,
    explanation: "Exploitation triggers the bug or behavior.",
  },
  {
    id: 20,
    topic: "Exploitation",
    question: "A defense against exploitation is:",
    options: ["Rapid patching and hardening", "Disabling logging", "Lowering alerting", "Removing backups"],
    correctAnswer: 0,
    explanation: "Patching removes exploitable vulnerabilities.",
  },
  {
    id: 21,
    topic: "Installation",
    question: "Installation refers to:",
    options: ["Placing malware or a backdoor", "Sending the payload", "Scanning the target", "Creating phishing sites"],
    correctAnswer: 0,
    explanation: "Installation is when malware is placed on the host.",
  },
  {
    id: 22,
    topic: "Installation",
    question: "A common installation goal is:",
    options: ["Persistence", "Shorter log files", "Faster backups", "DNS hardening"],
    correctAnswer: 0,
    explanation: "Attackers want persistence after initial access.",
  },
  {
    id: 23,
    topic: "Installation",
    question: "A defensive control for installation is:",
    options: ["Application allowlisting and EDR", "Disable MFA", "Allow macros", "Turn off logging"],
    correctAnswer: 0,
    explanation: "Allowlisting and EDR can block implants.",
  },
  {
    id: 24,
    topic: "C2",
    question: "Command and Control (C2) is:",
    options: ["A channel for remote control of malware", "A backup system", "A patch pipeline", "A DNS cache"],
    correctAnswer: 0,
    explanation: "C2 allows attackers to control infected hosts.",
  },
  {
    id: 25,
    topic: "C2",
    question: "A common C2 indicator is:",
    options: ["Regular beaconing to external domains", "Normal software updates", "Internal backups", "User training"],
    correctAnswer: 0,
    explanation: "Beaconing suggests remote control traffic.",
  },
  {
    id: 26,
    topic: "C2",
    question: "A defensive control against C2 is:",
    options: ["Egress filtering and DNS monitoring", "Disabling endpoints", "Stopping backups", "Removing SIEM"],
    correctAnswer: 0,
    explanation: "Egress controls limit outbound C2 traffic.",
  },
  {
    id: 27,
    topic: "Actions",
    question: "Actions on Objectives includes:",
    options: ["Data theft, disruption, or fraud", "Payload creation", "Email delivery", "Port scanning"],
    correctAnswer: 0,
    explanation: "This phase achieves the attacker goal.",
  },
  {
    id: 28,
    topic: "Actions",
    question: "A defensive control for actions on objectives is:",
    options: ["DLP, backups, and monitoring", "Disable logging", "Allow all traffic", "Turn off MFA"],
    correctAnswer: 0,
    explanation: "DLP and monitoring can detect exfiltration.",
  },
  {
    id: 29,
    topic: "Strategy",
    question: "The Kill Chain helps defenders by:",
    options: ["Mapping where to detect and disrupt attacks", "Replacing threat intel", "Eliminating logging", "Avoiding patching"],
    correctAnswer: 0,
    explanation: "It shows where to break the attack sequence.",
  },
  {
    id: 30,
    topic: "Strategy",
    question: "Stopping attacks earlier in the chain:",
    options: ["Reduces impact and cost", "Has no effect", "Increases damage", "Always delays response"],
    correctAnswer: 0,
    explanation: "Early detection limits attacker progress.",
  },
  {
    id: 31,
    topic: "Strategy",
    question: "The Kill Chain assumes attacks are:",
    options: ["Multi-stage with sequential steps", "Single-step only", "Only internal", "Only automated"],
    correctAnswer: 0,
    explanation: "The model breaks attacks into stages.",
  },
  {
    id: 32,
    topic: "Strategy",
    question: "Attackers may:",
    options: ["Skip or combine phases", "Always follow a perfect sequence", "Only use one phase", "Ignore delivery"],
    correctAnswer: 0,
    explanation: "Real attacks can skip or merge phases.",
  },
  {
    id: 33,
    topic: "Reconnaissance",
    question: "Reducing recon success includes:",
    options: ["Minimizing public exposure of details", "Publishing internal diagrams", "Sharing credentials", "Allowing public admin panels"],
    correctAnswer: 0,
    explanation: "Limit public information to reduce recon value.",
  },
  {
    id: 34,
    topic: "Reconnaissance",
    question: "Threat intel can help by:",
    options: ["Identifying recon patterns and targets", "Disabling patches", "Stopping logs", "Removing alerts"],
    correctAnswer: 0,
    explanation: "Intel reveals common recon behaviors.",
  },
  {
    id: 35,
    topic: "Weaponization",
    question: "Weaponization often includes:",
    options: ["Creating malicious documents or payloads", "Blocking emails", "Encrypting backups", "Deploying EDR"],
    correctAnswer: 0,
    explanation: "Attackers craft payloads for the target.",
  },
  {
    id: 36,
    topic: "Weaponization",
    question: "A macro-enabled document is typically used in:",
    options: ["Delivery and weaponization", "Only reconnaissance", "Only C2", "Only actions on objectives"],
    correctAnswer: 0,
    explanation: "Weaponized docs are delivered to victims.",
  },
  {
    id: 37,
    topic: "Delivery",
    question: "A watering hole attack is part of:",
    options: ["Delivery", "Installation", "C2", "Actions on Objectives"],
    correctAnswer: 0,
    explanation: "Watering holes deliver payloads via compromised sites.",
  },
  {
    id: 38,
    topic: "Delivery",
    question: "USB drop attacks fit into:",
    options: ["Delivery", "Exploitation", "C2", "Reconnaissance"],
    correctAnswer: 0,
    explanation: "USB drops deliver payloads to targets.",
  },
  {
    id: 39,
    topic: "Exploitation",
    question: "User-driven exploitation often involves:",
    options: ["Opening a malicious attachment", "Only kernel bugs", "Only DNS spoofing", "Only password resets"],
    correctAnswer: 0,
    explanation: "Users trigger exploits via malicious files or links.",
  },
  {
    id: 40,
    topic: "Exploitation",
    question: "Exploit kits are used to:",
    options: ["Automate exploitation via drive-by attacks", "Patch systems", "Detect malware", "Encrypt traffic"],
    correctAnswer: 0,
    explanation: "Exploit kits deliver and trigger vulnerabilities.",
  },
  {
    id: 41,
    topic: "Installation",
    question: "Persistence mechanisms include:",
    options: ["Startup services and scheduled tasks", "Firewall rule removal", "HTTPS enforcement", "Log rotation"],
    correctAnswer: 0,
    explanation: "Persistence keeps malware running after reboot.",
  },
  {
    id: 42,
    topic: "Installation",
    question: "A common indicator of installation is:",
    options: ["New autorun entries or services", "Normal OS updates", "User password change", "DNS cache flush"],
    correctAnswer: 0,
    explanation: "New persistence entries are suspicious.",
  },
  {
    id: 43,
    topic: "C2",
    question: "C2 traffic often uses:",
    options: ["HTTP, HTTPS, or DNS", "Only SMTP", "Only SMB", "Only ICMP"],
    correctAnswer: 0,
    explanation: "Common protocols help blend with normal traffic.",
  },
  {
    id: 44,
    topic: "C2",
    question: "Beaconing is:",
    options: ["Regular periodic communication to a server", "Large file transfer only", "A patch process", "A user login event"],
    correctAnswer: 0,
    explanation: "Beaconing is periodic C2 traffic.",
  },
  {
    id: 45,
    topic: "Actions",
    question: "Actions on objectives may include:",
    options: ["Data exfiltration", "Only reconnaissance", "Only delivery", "Only exploitation"],
    correctAnswer: 0,
    explanation: "Data theft is a common objective.",
  },
  {
    id: 46,
    topic: "Actions",
    question: "Ransomware impact typically falls under:",
    options: ["Actions on Objectives", "Reconnaissance", "Weaponization", "Delivery"],
    correctAnswer: 0,
    explanation: "Ransomware executes the attacker goal.",
  },
  {
    id: 47,
    topic: "Defenses",
    question: "Defense in depth means:",
    options: ["Controls at multiple phases", "Only perimeter defense", "Only endpoint defense", "Only logging"],
    correctAnswer: 0,
    explanation: "Layered defenses reduce single points of failure.",
  },
  {
    id: 48,
    topic: "Defenses",
    question: "Endpoint detection and response (EDR) helps with:",
    options: ["Installation and post-exploitation detection", "Weaponization", "Recon only", "Patch deployment only"],
    correctAnswer: 0,
    explanation: "EDR detects malicious behavior on hosts.",
  },
  {
    id: 49,
    topic: "Defenses",
    question: "Network monitoring helps detect:",
    options: ["Recon and C2 activity", "Only local file access", "Only kernel updates", "Only backups"],
    correctAnswer: 0,
    explanation: "Network telemetry shows scanning and beaconing.",
  },
  {
    id: 50,
    topic: "Defenses",
    question: "User awareness training helps reduce:",
    options: ["Phishing delivery success", "Patch failures", "ASLR entropy", "Disk fragmentation"],
    correctAnswer: 0,
    explanation: "Training reduces click rates on phishing.",
  },
  {
    id: 51,
    topic: "Defenses",
    question: "Application allowlisting helps prevent:",
    options: ["Unauthorized malware execution", "DNS lookups", "Patch installs", "Log rotation"],
    correctAnswer: 0,
    explanation: "Allowlisting blocks unknown executables.",
  },
  {
    id: 52,
    topic: "Defenses",
    question: "Segmentation helps reduce:",
    options: ["Lateral movement and impact", "Patch speed", "DNS resolution", "Email delivery"],
    correctAnswer: 0,
    explanation: "Segmentation limits attacker spread.",
  },
  {
    id: 53,
    topic: "Defenses",
    question: "Backups are most helpful in:",
    options: ["Recovering from actions on objectives", "Preventing recon", "Building payloads", "Email delivery"],
    correctAnswer: 0,
    explanation: "Backups support recovery from ransomware.",
  },
  {
    id: 54,
    topic: "Mapping",
    question: "Mapping alerts to the Kill Chain helps:",
    options: ["Prioritize response by phase", "Disable triage", "Remove alerts", "Avoid documentation"],
    correctAnswer: 0,
    explanation: "Phase mapping guides response urgency.",
  },
  {
    id: 55,
    topic: "Mapping",
    question: "Kill Chain is often used with:",
    options: ["MITRE ATT&CK for tactics and techniques", "Only OSI model", "Only CVSS scoring", "Only CVE lists"],
    correctAnswer: 0,
    explanation: "ATT&CK provides detailed technique mapping.",
  },
  {
    id: 56,
    topic: "Reconnaissance",
    question: "Recon mitigation includes:",
    options: ["Monitoring brand abuse and leaks", "Disabling AV", "Allowing directory listing", "Disabling DNS logs"],
    correctAnswer: 0,
    explanation: "Brand and leak monitoring reduces recon success.",
  },
  {
    id: 57,
    topic: "Weaponization",
    question: "Threat actors may reuse:",
    options: ["Known exploits and commodity malware", "Only internal tools", "Only blue team tools", "Only open proxies"],
    correctAnswer: 0,
    explanation: "Commodity tooling is common in weaponization.",
  },
  {
    id: 58,
    topic: "Delivery",
    question: "Drive-by downloads are part of:",
    options: ["Delivery", "Reconnaissance", "C2", "Actions on Objectives"],
    correctAnswer: 0,
    explanation: "They deliver payloads via compromised sites.",
  },
  {
    id: 59,
    topic: "Exploitation",
    question: "Exploit mitigation includes:",
    options: ["Patching and exploit prevention", "Only logs", "Only DNS filtering", "Only backups"],
    correctAnswer: 0,
    explanation: "Mitigations reduce exploit success.",
  },
  {
    id: 60,
    topic: "Installation",
    question: "Malware installation often creates:",
    options: ["Persistence artifacts", "Firewall rules only", "DNS zones", "TLS certificates"],
    correctAnswer: 0,
    explanation: "Persistence ensures malware survives reboots.",
  },
  {
    id: 61,
    topic: "C2",
    question: "C2 over DNS is used to:",
    options: ["Blend with common traffic", "Disable logging", "Patch systems", "Change passwords"],
    correctAnswer: 0,
    explanation: "DNS is often allowed and can be abused.",
  },
  {
    id: 62,
    topic: "Actions",
    question: "Data staging before exfiltration occurs in:",
    options: ["Actions on Objectives", "Reconnaissance", "Weaponization", "Delivery"],
    correctAnswer: 0,
    explanation: "Staging is part of achieving objectives.",
  },
  {
    id: 63,
    topic: "Strategy",
    question: "Disrupting any phase of the chain:",
    options: ["Can stop the attack progression", "Has no effect", "Always increases impact", "Only delays patching"],
    correctAnswer: 0,
    explanation: "Breaking one phase can halt the attack.",
  },
  {
    id: 64,
    topic: "Strategy",
    question: "Kill Chain limitations include:",
    options: ["Not covering all modern attack patterns", "Being too detailed", "Replacing ATT&CK", "Only for insiders"],
    correctAnswer: 0,
    explanation: "Some attacks skip phases or move non-linearly.",
  },
  {
    id: 65,
    topic: "Strategy",
    question: "The model is most useful for:",
    options: ["Targeted intrusion campaigns", "Only commodity malware", "Only insider threats", "Only physical attacks"],
    correctAnswer: 0,
    explanation: "It was designed for targeted intrusions.",
  },
  {
    id: 66,
    topic: "Indicators",
    question: "Indicators for delivery include:",
    options: ["Phishing emails and malicious links", "Kernel panics", "Normal backups", "Time sync events"],
    correctAnswer: 0,
    explanation: "Suspicious emails and links are delivery signs.",
  },
  {
    id: 67,
    topic: "Indicators",
    question: "Indicators for exploitation include:",
    options: ["Crash logs or exploit signatures", "Routine logins", "Healthy backups", "Patch success"],
    correctAnswer: 0,
    explanation: "Crashes and exploit patterns can indicate exploitation.",
  },
  {
    id: 68,
    topic: "Indicators",
    question: "Indicators for installation include:",
    options: ["New services or startup entries", "Normal OS updates", "Printer events", "DNS cache flushes"],
    correctAnswer: 0,
    explanation: "New persistence artifacts are suspicious.",
  },
  {
    id: 69,
    topic: "Indicators",
    question: "Indicators for C2 include:",
    options: ["Periodic outbound beacons", "Local log rotation", "User logoff events", "Backup completion"],
    correctAnswer: 0,
    explanation: "Regular beacons suggest C2 activity.",
  },
  {
    id: 70,
    topic: "Indicators",
    question: "Indicators for actions on objectives include:",
    options: ["Large outbound data transfers", "Normal patching", "Printer use", "User onboarding"],
    correctAnswer: 0,
    explanation: "Large outbound transfers can indicate exfiltration.",
  },
  {
    id: 71,
    topic: "Response",
    question: "During response, mapping to phases helps:",
    options: ["Identify where to contain first", "Disable alerts", "Avoid documentation", "Ignore telemetry"],
    correctAnswer: 0,
    explanation: "Phase mapping clarifies response priorities.",
  },
  {
    id: 72,
    topic: "Response",
    question: "If you detect delivery, a strong response is to:",
    options: ["Block the payload and isolate targets", "Wait for exploitation", "Disable all logging", "Ignore alerts"],
    correctAnswer: 0,
    explanation: "Stopping delivery prevents later phases.",
  },
  {
    id: 73,
    topic: "Response",
    question: "If you detect C2 traffic, you should:",
    options: ["Contain the host and block the channel", "Do nothing", "Disable backups", "Delete logs"],
    correctAnswer: 0,
    explanation: "Containment stops attacker control.",
  },
  {
    id: 74,
    topic: "Response",
    question: "Incident reports should include:",
    options: ["Kill Chain phase mapping and evidence", "Only a summary line", "Only ticket numbers", "No timestamps"],
    correctAnswer: 0,
    explanation: "Phase mapping improves understanding and response.",
  },
  {
    id: 75,
    topic: "Summary",
    question: "The key idea of the Kill Chain is to:",
    options: ["Break the attack sequence at any phase", "Only focus on the last phase", "Ignore early signals", "Replace all other frameworks"],
    correctAnswer: 0,
    explanation: "Disrupting any phase can stop the attack.",
  },
];

export default function KillChainPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [expandedPhase, setExpandedPhase] = useState<number | false>(false);

  const pageContext = `Cyber Kill Chain educational page. This page teaches the Lockheed Martin Cyber Kill Chain framework including all 7 phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, and Actions on Objectives. It covers attack techniques and defensive measures for each phase.`;

  return (
    <LearnPageLayout pageTitle="Cyber Kill Chain" pageContext={pageContext}>
    <Container maxWidth="lg" sx={{ py: 4 }}>
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

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #ef4444, #a855f7)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          ⚔️ Cyber Kill Chain
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          The Lockheed Martin Cyber Kill Chain® is a framework describing the stages of a targeted cyberattack. Understanding each phase helps defenders identify and stop attacks before damage occurs.
        </Typography>
      </Box>

      {/* Overview Section */}
      <Paper
        sx={{
          p: 4,
          mb: 5,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#6366f1", 0.05)}, ${alpha("#dc2626", 0.05)})`,
        }}
      >
        <Grid container spacing={4}>
          <Grid item xs={12} md={7}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
              Why the Kill Chain Matters
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              Developed by Lockheed Martin in 2011, the Cyber Kill Chain breaks down cyberattacks into 7 sequential phases. This model helps security teams understand attacker methodology, identify where attacks can be detected and stopped, and measure defensive capabilities at each stage.
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
              <strong>Key Insight:</strong> Breaking ANY single link in the chain stops the attack. Early detection (phases 1-3) is ideal, but defenses should exist at every phase for defense in depth.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              <Chip label="7 Phases" sx={{ bgcolor: alpha("#6366f1", 0.1), color: "#6366f1", fontWeight: 600 }} />
              <Chip label="Defense in Depth" variant="outlined" />
              <Chip label="Lockheed Martin" variant="outlined" />
              <Chip label="Threat Intelligence" variant="outlined" />
            </Box>
          </Grid>
          <Grid item xs={12} md={5}>
            <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>Remember:</strong> Attackers only need to succeed once. Defenders must succeed at every phase.
              </Typography>
            </Alert>
            <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 3, borderRadius: 2, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2 }}>Quick Reference</Typography>
              {killChainPhases.map((phase) => (
                <Box
                  key={phase.id}
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 1.5,
                    mb: 1,
                    cursor: "pointer",
                    p: 0.5,
                    borderRadius: 1,
                    "&:hover": { bgcolor: alpha(phase.color, 0.1) },
                  }}
                  onClick={() => setExpandedPhase(phase.id)}
                >
                  <Box sx={{ color: phase.color, display: "flex" }}>{phase.icon}</Box>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {phase.id}. {phase.name}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Visual Chain */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        🔗 The 7 Phases
      </Typography>
      <Box
        sx={{
          display: "flex",
          overflowX: "auto",
          gap: 1,
          mb: 5,
          pb: 2,
          "&::-webkit-scrollbar": { height: 6 },
          "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.palette.primary.main, 0.3), borderRadius: 3 },
        }}
      >
        {killChainPhases.map((phase, index) => (
          <Box
            key={phase.id}
            onClick={() => setExpandedPhase(phase.id)}
            sx={{
              display: "flex",
              alignItems: "center",
              flexShrink: 0,
              cursor: "pointer",
            }}
          >
            <Paper
              sx={{
                px: 3,
                py: 2,
                borderRadius: 2,
                bgcolor: expandedPhase === phase.id ? alpha(phase.color, 0.15) : alpha(phase.color, 0.05),
                border: `2px solid ${expandedPhase === phase.id ? phase.color : "transparent"}`,
                transition: "all 0.2s",
                "&:hover": { bgcolor: alpha(phase.color, 0.1), transform: "translateY(-2px)" },
                minWidth: 140,
                textAlign: "center",
              }}
            >
              <Box sx={{ color: phase.color, mb: 1 }}>{phase.icon}</Box>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: phase.color }}>
                {phase.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Phase {phase.id}
              </Typography>
            </Paper>
            {index < killChainPhases.length - 1 && (
              <Box sx={{ px: 1, color: "text.disabled", fontSize: "1.5rem" }}>→</Box>
            )}
          </Box>
        ))}
      </Box>

      {/* Phase Details */}
      <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
        📋 Detailed Phase Breakdown
      </Typography>
      {killChainPhases.map((phase) => (
        <Accordion
          key={phase.id}
          expanded={expandedPhase === phase.id}
          onChange={(_, expanded) => setExpandedPhase(expanded ? phase.id : false)}
          sx={{
            mb: 2,
            borderRadius: 2,
            "&:before": { display: "none" },
            border: `1px solid ${alpha(phase.color, 0.2)}`,
            "&.Mui-expanded": { border: `2px solid ${phase.color}` },
          }}
        >
          <AccordionSummary
            expandIcon={<ExpandMoreIcon />}
            sx={{
              bgcolor: alpha(phase.color, 0.05),
              borderRadius: "8px 8px 0 0",
              "&.Mui-expanded": { borderBottom: `1px solid ${alpha(phase.color, 0.2)}` },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ p: 1, borderRadius: 2, bgcolor: alpha(phase.color, 0.15), color: phase.color }}>
                {phase.icon}
              </Box>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700 }}>
                  Phase {phase.id}: {phase.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {phase.subtitle}
                </Typography>
              </Box>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ p: 4 }}>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              {phase.description}
            </Typography>

            <Grid container spacing={4}>
              {/* Attacker Actions */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon fontSize="small" /> Attacker Actions
                  </Typography>
                  <List dense>
                    {phase.attackerActions.map((action, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="error.main">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={action} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>

              {/* Defender Actions */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <ShieldIcon fontSize="small" /> Defender Actions
                  </Typography>
                  <List dense>
                    {phase.defenderActions.map((action, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Typography variant="body2" color="success.main">•</Typography>
                        </ListItemIcon>
                        <ListItemText primary={action} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            {/* Tools & Indicators */}
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🛠️ Common Tools</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {phase.tools.map((tool) => (
                    <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.75rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5 }}>🔍 Detection Indicators</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {phase.indicators.map((indicator) => (
                    <Chip key={indicator} label={indicator} size="small" sx={{ fontSize: "0.75rem", bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
                  ))}
                </Box>
              </Grid>
            </Grid>

            {/* Real World Example */}
            <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Real-World Example</Typography>
              <Typography variant="body2">{phase.realWorldExample}</Typography>
            </Alert>
          </AccordionDetails>
        </Accordion>
      ))}

      {/* Footer */}
      <Paper sx={{ p: 4, mt: 4, borderRadius: 3, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          🎓 Key Takeaways
        </Typography>
        <Grid container spacing={2}>
          {[
            "Early detection is best - stopping reconnaissance or delivery prevents all later phases",
            "Defense in depth is critical - have controls at every phase",
            "Threat intelligence helps identify patterns across the chain",
            "Modern attacks may skip or combine phases (e.g., supply chain attacks)",
          ].map((point, i) => (
            <Grid item xs={12} md={6} key={i}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Chip label={i + 1} size="small" sx={{ bgcolor: "info.main", color: "white", fontWeight: 700, minWidth: 24, height: 24 }} />
                <Typography variant="body2">{point}</Typography>
              </Box>
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
          title="Cyber Kill Chain Knowledge Check"
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
