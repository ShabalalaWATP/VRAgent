import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  useMediaQuery,
  Chip,
  Grid,
  Card,
  CardContent,
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
  Divider,
  Alert,
  AlertTitle,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Drawer,
  Fab,
} from "@mui/material";
import { useState, useEffect } from "react";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useNavigate, Link } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import ListAltIcon from "@mui/icons-material/ListAlt";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";

// Page context for AI chat
const pageContext = `This is a comprehensive Incident Response Guide based on the NIST SP 800-61 framework covering:

1. IR Phases (NIST Framework):
- Preparation: IR policies, team building, tools, communication channels
- Detection & Analysis: Monitoring, alert triage, IOC identification, severity classification
- Containment: Short-term and long-term containment strategies, evidence preservation
- Eradication: Root cause identification, malware removal, vulnerability patching
- Recovery: System restoration, backup verification, enhanced monitoring
- Lessons Learned: Post-incident review, gap analysis, procedure updates

2. Incident Types & Response:
- Malware/Ransomware: Detection indicators, investigation queries, containment steps
- Phishing/BEC: Email compromise, credential theft, wire fraud prevention
- Data Breach: Impact assessment, regulatory notification requirements
- Insider Threat: Coordination with HR/Legal, monitoring strategies
- DDoS Attack: Mitigation engagement, traffic analysis
- Unauthorized Access: Account compromise, privilege escalation detection
- Supply Chain Attack: Software/vendor compromise response
- Cryptojacking: Mining detection and removal

3. Playbooks:
- Ransomware Response Playbook (immediate actions, investigation, recovery)
- Phishing/Credential Compromise Playbook
- Data Breach Response Playbook

4. Detection & Monitoring:
- Critical Windows Event IDs (4624, 4625, 4688, 4698, etc.)
- Key data sources (Windows logs, network traffic, EDR, cloud)
- Sigma detection rules
- MITRE ATT&CK detection mapping

5. IR Tools:
- Collection: Velociraptor, KAPE, FTK Imager
- Memory Forensics: Volatility 3
- Timeline: Plaso/log2timeline
- Log Analysis: Chainsaw, Hayabusa
- Case Management: TheHive, MISP
- Quick collection commands for Windows and Linux

6. Documentation:
- Essential templates (incident ticket, evidence log, timeline)
- Communication templates (stakeholder notification, executive briefing)
- Regulatory requirements (GDPR, HIPAA, PCI DSS, SOX, NIS2)
- Incident report and chain of custody templates

7. Readiness & Coordination:
- Readiness checklist and IR hygiene
- Stakeholder notification matrix
- Evidence handling quick checklist
- Communication cadence guidance

8. Resources:
- Standards & frameworks (NIST, SANS, CISA)
- Training & certifications (GCIH, GCFA, FOR508)
- Practice labs (CyberDefenders, Blue Team Labs)`; 
import ShieldIcon from "@mui/icons-material/Shield";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import SearchIcon from "@mui/icons-material/Search";
import BuildIcon from "@mui/icons-material/Build";
import RestoreIcon from "@mui/icons-material/Restore";
import SchoolIcon from "@mui/icons-material/School";
import AssignmentIcon from "@mui/icons-material/Assignment";
import TimelineIcon from "@mui/icons-material/Timeline";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CancelIcon from "@mui/icons-material/Cancel";
import InfoIcon from "@mui/icons-material/Info";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StorageIcon from "@mui/icons-material/Storage";
import ComputerIcon from "@mui/icons-material/Computer";
import CloudIcon from "@mui/icons-material/Cloud";
import EmailIcon from "@mui/icons-material/Email";
import LockIcon from "@mui/icons-material/Lock";
import GroupIcon from "@mui/icons-material/Group";
import ArticleIcon from "@mui/icons-material/Article";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import DnsIcon from "@mui/icons-material/Dns";
import MemoryIcon from "@mui/icons-material/Memory";
import FolderIcon from "@mui/icons-material/Folder";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import TerminalIcon from "@mui/icons-material/Terminal";
import DataObjectIcon from "@mui/icons-material/DataObject";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import PolicyIcon from "@mui/icons-material/Policy";
import GavelIcon from "@mui/icons-material/Gavel";
import NotificationsActiveIcon from "@mui/icons-material/NotificationsActive";
import SpeedIcon from "@mui/icons-material/Speed";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import AnalyticsIcon from "@mui/icons-material/Analytics";
import QuizIcon from "@mui/icons-material/Quiz";
import MenuBookIcon from "@mui/icons-material/MenuBook";

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#3b82f6";

// Theme colors for consistent styling
const themeColors = {
  primary: "#ef4444",
  primaryLight: "#f87171",
  secondary: "#f59e0b",
  accent: "#3b82f6",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(239, 68, 68, 0.2)",
  textMuted: "#94a3b8",
};

// Section navigation items
const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: SchoolIcon },
  { id: "overview", label: "Overview", icon: SecurityIcon },
  { id: "ir-phases", label: "IR Phases", icon: TimelineIcon },
  { id: "incident-types", label: "Incident Types", icon: WarningAmberIcon },
  { id: "playbooks", label: "Playbooks", icon: AssignmentIcon },
  { id: "detection", label: "Detection", icon: SearchIcon },
  { id: "tools", label: "Tools", icon: BuildIcon },
  { id: "documentation", label: "Documentation", icon: ArticleIcon },
  { id: "resources", label: "Resources", icon: MenuBookIcon },
  { id: "quiz-section", label: "Knowledge Check", icon: QuizIcon },
];

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Which framework is commonly referenced for incident response phases?",
    options: ["NIST SP 800-61", "OWASP ASVS", "CIS Benchmark", "ISO 9001"],
    correctAnswer: 0,
    explanation: "NIST SP 800-61 outlines the standard IR lifecycle phases.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The first phase in the NIST incident response lifecycle is:",
    options: ["Detection and Analysis", "Preparation", "Containment", "Recovery"],
    correctAnswer: 1,
    explanation: "Preparation ensures policies, tools, and teams are ready before incidents.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "The primary goal of containment is to:",
    options: ["Collect marketing data", "Stop the spread and limit impact", "Replace backups", "Draft press releases"],
    correctAnswer: 1,
    explanation: "Containment focuses on limiting damage and preventing further compromise.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Eradication involves:",
    options: ["Removing malware and closing attack vectors", "Only isolating systems", "Only notifying users", "Only collecting logs"],
    correctAnswer: 0,
    explanation: "Eradication removes the threat and fixes root causes.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Recovery is about:",
    options: ["Restoring systems and validating normal operations", "Deleting all logs", "Rebooting without analysis", "Ignoring monitoring"],
    correctAnswer: 0,
    explanation: "Recovery restores services safely and verifies integrity.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "Lessons learned should be conducted:",
    options: ["Before an incident", "After containment and recovery", "Only if required by law", "Only by executives"],
    correctAnswer: 1,
    explanation: "Post-incident reviews improve future response and controls.",
  },
  {
    id: 7,
    topic: "Triage",
    question: "Incident triage is used to:",
    options: ["Assign severity and prioritize response", "Delete alerts", "Replace firewall rules", "Disable MFA"],
    correctAnswer: 0,
    explanation: "Triage prioritizes incidents based on impact and urgency.",
  },
  {
    id: 8,
    topic: "Triage",
    question: "MTTD stands for:",
    options: ["Mean Time to Detect", "Mean Time to Deploy", "Maximum Time to Decision", "Mean Time to Document"],
    correctAnswer: 0,
    explanation: "MTTD measures how quickly incidents are detected.",
  },
  {
    id: 9,
    topic: "Triage",
    question: "MTTR commonly means:",
    options: ["Mean Time to Respond", "Maximum Time to Repair", "Mean Time to Report", "Minimum Time to Resolve"],
    correctAnswer: 0,
    explanation: "MTTR measures how quickly incidents are contained or resolved.",
  },
  {
    id: 10,
    topic: "Triage",
    question: "A false positive is:",
    options: ["Benign activity flagged as malicious", "Malicious activity missed", "A confirmed breach", "An incident report"],
    correctAnswer: 0,
    explanation: "False positives are benign events incorrectly flagged as incidents.",
  },
  {
    id: 11,
    topic: "Evidence",
    question: "Why preserve evidence before remediation?",
    options: ["To improve system performance", "To support investigation and legal needs", "To delay recovery", "To reduce staffing needs"],
    correctAnswer: 1,
    explanation: "Preserving evidence enables accurate analysis and legal defensibility.",
  },
  {
    id: 12,
    topic: "Evidence",
    question: "The chain of custody documents:",
    options: ["System uptime", "Evidence handling history", "Network routes", "Password changes"],
    correctAnswer: 1,
    explanation: "Chain of custody tracks evidence collection and handling.",
  },
  {
    id: 13,
    topic: "Evidence",
    question: "Which should be collected first due to volatility?",
    options: ["RAM and running processes", "Archived backups", "Static documentation", "Vendor contracts"],
    correctAnswer: 0,
    explanation: "Volatile data like memory is lost quickly and must be captured early.",
  },
  {
    id: 14,
    topic: "Evidence",
    question: "Hashing evidence is used to:",
    options: ["Encrypt files", "Verify integrity of collected data", "Compress files", "Hide filenames"],
    correctAnswer: 1,
    explanation: "Hashes verify evidence has not changed.",
  },
  {
    id: 15,
    topic: "Evidence",
    question: "A forensic image should be created:",
    options: ["After wiping the disk", "Before making changes to the original", "Only if time permits", "Only for cloud systems"],
    correctAnswer: 1,
    explanation: "Imaging preserves original evidence before remediation.",
  },
  {
    id: 16,
    topic: "Containment",
    question: "Short-term containment often involves:",
    options: ["Network isolation and account disabling", "Final report writing", "Backup archival", "Vendor procurement"],
    correctAnswer: 0,
    explanation: "Immediate actions limit spread and reduce damage.",
  },
  {
    id: 17,
    topic: "Containment",
    question: "Long-term containment focuses on:",
    options: ["Sustained controls and segmentation", "Deleting all logs", "Turning off monitoring", "Skipping patching"],
    correctAnswer: 0,
    explanation: "Long-term containment stabilizes the environment while remediation continues.",
  },
  {
    id: 18,
    topic: "Containment",
    question: "Why avoid tipping off the attacker?",
    options: ["It increases risk of data loss or evasion", "It speeds up recovery", "It improves alerts", "It reduces monitoring"],
    correctAnswer: 0,
    explanation: "Alerting attackers can cause them to destroy evidence or expand access.",
  },
  {
    id: 19,
    topic: "Containment",
    question: "DNS sinkholing is used to:",
    options: ["Block known malicious domains and observe callbacks", "Speed up DNS", "Encrypt traffic", "Disable logs"],
    correctAnswer: 0,
    explanation: "Sinkholes can block and observe malicious connections.",
  },
  {
    id: 20,
    topic: "Containment",
    question: "Why disable accounts instead of deleting them?",
    options: ["Preserve evidence and audit trail", "Reduce storage use", "Remove MFA", "Increase performance"],
    correctAnswer: 0,
    explanation: "Disabling preserves evidence while preventing access.",
  },
  {
    id: 21,
    topic: "Detection",
    question: "Which data source is most useful for initial triage?",
    options: ["SIEM alerts and endpoint telemetry", "Office seating charts", "HR vacation schedules", "Marketing analytics"],
    correctAnswer: 0,
    explanation: "SIEM and endpoint data provide fast visibility into incidents.",
  },
  {
    id: 22,
    topic: "Detection",
    question: "An IOC is:",
    options: ["A sign of compromise such as a hash or domain", "A ticketing system", "A firewall rule", "A user role"],
    correctAnswer: 0,
    explanation: "IOCs are artifacts indicating potential compromise.",
  },
  {
    id: 23,
    topic: "Detection",
    question: "An IOA indicates:",
    options: ["Attack behavior in progress", "A completed backup", "A patch cycle", "A login success"],
    correctAnswer: 0,
    explanation: "IOAs focus on behaviors that show active attack patterns.",
  },
  {
    id: 24,
    topic: "Detection",
    question: "Event ID 4625 (Windows) indicates:",
    options: ["Failed logon", "Service creation", "Log cleared", "Privilege assignment"],
    correctAnswer: 0,
    explanation: "4625 is a failed logon event.",
  },
  {
    id: 25,
    topic: "Detection",
    question: "A spike in failed logins could indicate:",
    options: ["Brute force or password spraying", "A successful patch", "Normal backups", "Hardware upgrade"],
    correctAnswer: 0,
    explanation: "Repeated failures often signal credential attacks.",
  },
  {
    id: 26,
    topic: "Eradication",
    question: "Root cause analysis helps by:",
    options: ["Preventing recurrence by fixing the real issue", "Delaying response", "Reducing monitoring", "Avoiding documentation"],
    correctAnswer: 0,
    explanation: "RCA identifies the underlying weakness to fix.",
  },
  {
    id: 27,
    topic: "Eradication",
    question: "Rebuilding a system from a known-good image is often:",
    options: ["Safer than attempting manual cleanup", "Always unnecessary", "Slower and less reliable", "Only for laptops"],
    correctAnswer: 0,
    explanation: "Rebuilding ensures removal of hidden persistence.",
  },
  {
    id: 28,
    topic: "Eradication",
    question: "Credential resets should include:",
    options: ["Service accounts and privileged users", "Only guest accounts", "Only email users", "No privileged users"],
    correctAnswer: 0,
    explanation: "Privileged and service accounts are common targets.",
  },
  {
    id: 29,
    topic: "Eradication",
    question: "Why scan with multiple tools?",
    options: ["Increase detection coverage", "Reduce evidence", "Speed up logs", "Avoid patching"],
    correctAnswer: 0,
    explanation: "Different tools can find different artifacts.",
  },
  {
    id: 30,
    topic: "Eradication",
    question: "Removing persistence mechanisms means:",
    options: ["Deleting scheduled tasks, services, or run keys", "Only deleting user files", "Only rebooting", "Only changing passwords"],
    correctAnswer: 0,
    explanation: "Persistence often uses tasks, services, or registry keys.",
  },
  {
    id: 31,
    topic: "Recovery",
    question: "Recovery should include:",
    options: ["Enhanced monitoring after restoration", "Turning off logs", "Removing security tools", "Skipping validation"],
    correctAnswer: 0,
    explanation: "Monitoring detects re-infection or missed artifacts.",
  },
  {
    id: 32,
    topic: "Recovery",
    question: "Restoring from backups requires:",
    options: ["Verifying backup integrity first", "Assuming backups are safe", "Skipping patching", "No validation"],
    correctAnswer: 0,
    explanation: "Backups can be compromised and must be verified.",
  },
  {
    id: 33,
    topic: "Recovery",
    question: "A phased return to production helps:",
    options: ["Reduce risk of re-infection and instability", "Hide issues", "Avoid monitoring", "Increase downtime"],
    correctAnswer: 0,
    explanation: "Phased recovery reduces risk and allows validation.",
  },
  {
    id: 34,
    topic: "Recovery",
    question: "Post-recovery validation should confirm:",
    options: ["Systems are functional and clean", "Only that logs exist", "Only that accounts reset", "Only that backups ran"],
    correctAnswer: 0,
    explanation: "Validation ensures normal operations and security.",
  },
  {
    id: 35,
    topic: "Recovery",
    question: "Which is a recovery deliverable?",
    options: ["Restored services and monitored stability", "A draft marketing plan", "Unused logs", "Unreviewed alerts"],
    correctAnswer: 0,
    explanation: "Recovery focuses on restoring and validating services.",
  },
  {
    id: 36,
    topic: "Communication",
    question: "Who should be included in an IR communication plan?",
    options: ["Security, IT, legal, and key stakeholders", "Only the SOC", "Only executives", "Only vendors"],
    correctAnswer: 0,
    explanation: "IR requires coordinated communications across teams.",
  },
  {
    id: 37,
    topic: "Communication",
    question: "Why use an out-of-band channel?",
    options: ["Primary channels may be compromised", "It is always faster", "It replaces evidence", "It disables MFA"],
    correctAnswer: 0,
    explanation: "Out-of-band communication reduces attacker visibility.",
  },
  {
    id: 38,
    topic: "Communication",
    question: "Regulatory notification should be handled with:",
    options: ["Legal and compliance guidance", "Only IT approval", "No documentation", "Public release first"],
    correctAnswer: 0,
    explanation: "Regulatory obligations require legal oversight.",
  },
  {
    id: 39,
    topic: "Communication",
    question: "An incident report should include:",
    options: ["Timeline, impact, and actions taken", "Only system names", "Only IP addresses", "Only a summary title"],
    correctAnswer: 0,
    explanation: "Reports should document timeline, impact, and response actions.",
  },
  {
    id: 40,
    topic: "Communication",
    question: "Stakeholder notifications should be:",
    options: ["Timely and coordinated", "Delayed until after cleanup", "Unstructured", "Only verbal"],
    correctAnswer: 0,
    explanation: "Timely and coordinated communication is essential.",
  },
  {
    id: 41,
    topic: "Tools",
    question: "Volatility is commonly used for:",
    options: ["Memory forensics", "DNS resolution", "Patch management", "Email filtering"],
    correctAnswer: 0,
    explanation: "Volatility analyzes RAM dumps.",
  },
  {
    id: 42,
    topic: "Tools",
    question: "KAPE is used for:",
    options: ["Rapid artifact collection", "Firewall management", "Email security", "Disk encryption"],
    correctAnswer: 0,
    explanation: "KAPE collects artifacts quickly during IR.",
  },
  {
    id: 43,
    topic: "Tools",
    question: "TheHive is primarily a:",
    options: ["Case management platform", "Packet sniffer", "Firewall", "Backup tool"],
    correctAnswer: 0,
    explanation: "TheHive supports case tracking and collaboration.",
  },
  {
    id: 44,
    topic: "Tools",
    question: "MISP is commonly used for:",
    options: ["Threat intel sharing and IOCs", "Disk imaging", "Memory capture", "Endpoint isolation"],
    correctAnswer: 0,
    explanation: "MISP manages and shares threat intelligence.",
  },
  {
    id: 45,
    topic: "Tools",
    question: "FTK Imager is used for:",
    options: ["Forensic disk imaging", "Network capture", "TLS inspection", "Log correlation"],
    correctAnswer: 0,
    explanation: "FTK Imager creates forensic images of disks.",
  },
  {
    id: 46,
    topic: "Forensics",
    question: "The order of volatility says to collect:",
    options: ["Volatile data before persistent data", "Disk before memory", "Backups before logs", "Reports before evidence"],
    correctAnswer: 0,
    explanation: "Volatile evidence must be captured first.",
  },
  {
    id: 47,
    topic: "Forensics",
    question: "Why use a write blocker?",
    options: ["Prevent changes to evidence media", "Speed up imaging", "Encrypt the disk", "Reset passwords"],
    correctAnswer: 0,
    explanation: "Write blockers protect evidence integrity.",
  },
  {
    id: 48,
    topic: "Forensics",
    question: "Which is an example of volatile evidence?",
    options: ["RAM contents", "Archived logs", "Printed policies", "Vendor invoices"],
    correctAnswer: 0,
    explanation: "RAM is volatile and disappears on power loss.",
  },
  {
    id: 49,
    topic: "Forensics",
    question: "When collecting logs, timestamps should be:",
    options: ["Recorded in UTC", "Recorded in local time only", "Rounded to the hour", "Removed for privacy"],
    correctAnswer: 0,
    explanation: "UTC ensures consistency across systems and time zones.",
  },
  {
    id: 50,
    topic: "Forensics",
    question: "An evidence log should include:",
    options: ["Who collected, when, where, and hash values", "Only file names", "Only a case ID", "Only system owners"],
    correctAnswer: 0,
    explanation: "Evidence logs capture full handling and integrity details.",
  },
  {
    id: 51,
    topic: "Incident Types",
    question: "Ransomware indicators often include:",
    options: ["Mass file encryption and ransom notes", "Only failed logins", "Only DNS timeouts", "Only printer errors"],
    correctAnswer: 0,
    explanation: "Ransomware commonly encrypts files and drops notes.",
  },
  {
    id: 52,
    topic: "Incident Types",
    question: "Phishing investigations should check for:",
    options: ["Mailbox rules and OAuth app consent", "Only disk usage", "Only patch levels", "Only backups"],
    correctAnswer: 0,
    explanation: "Compromised accounts may add rules or grant app access.",
  },
  {
    id: 53,
    topic: "Incident Types",
    question: "Data breach response should include:",
    options: ["Scope assessment and legal notification planning", "Only system rebuilds", "Only password resets", "Only firewall updates"],
    correctAnswer: 0,
    explanation: "Scope and legal requirements are critical in breaches.",
  },
  {
    id: 54,
    topic: "Incident Types",
    question: "Insider threat response requires:",
    options: ["Coordination with HR and legal", "Public disclosure", "Disabling all accounts", "Ignoring evidence"],
    correctAnswer: 0,
    explanation: "Insider cases require careful legal and HR coordination.",
  },
  {
    id: 55,
    topic: "Incident Types",
    question: "DDoS response should include:",
    options: ["Engaging mitigation services and analyzing traffic", "Forensic imaging only", "Disabling backups", "Password resets only"],
    correctAnswer: 0,
    explanation: "DDoS requires traffic analysis and mitigation.",
  },
  {
    id: 56,
    topic: "Incident Types",
    question: "Unauthorized access often involves:",
    options: ["Credential abuse or privilege escalation", "Only CPU spikes", "Only patch failures", "Only DNS errors"],
    correctAnswer: 0,
    explanation: "Credential abuse and privilege escalation are common.",
  },
  {
    id: 57,
    topic: "Incident Types",
    question: "Supply chain incidents may involve:",
    options: ["Compromised vendor software updates", "Only internal phishing", "Only physical theft", "Only DNS misconfigurations"],
    correctAnswer: 0,
    explanation: "Supply chain attacks exploit vendor or software distribution paths.",
  },
  {
    id: 58,
    topic: "Incident Types",
    question: "Cryptojacking indicators include:",
    options: ["Unusual CPU usage and mining processes", "Only file deletions", "Only network outages", "Only login prompts"],
    correctAnswer: 0,
    explanation: "Mining malware often causes sustained CPU spikes.",
  },
  {
    id: 59,
    topic: "Incident Types",
    question: "Business Email Compromise often attempts to:",
    options: ["Redirect payments or request urgent transfers", "Encrypt databases", "Disable backups", "Patch systems"],
    correctAnswer: 0,
    explanation: "BEC aims to trick staff into fraudulent payments.",
  },
  {
    id: 60,
    topic: "Incident Types",
    question: "A common sign of lateral movement is:",
    options: ["Unusual remote service usage", "A completed backup", "Normal login hours", "CPU idle"],
    correctAnswer: 0,
    explanation: "Unusual remote access may indicate lateral movement.",
  },
  {
    id: 61,
    topic: "Metrics",
    question: "Reducing MTTD improves:",
    options: ["Time to detect incidents", "Amount of storage used", "Number of users", "Patch frequency"],
    correctAnswer: 0,
    explanation: "Lower MTTD means faster detection.",
  },
  {
    id: 62,
    topic: "Metrics",
    question: "Reducing MTTR improves:",
    options: ["Speed of response and recovery", "Network bandwidth", "Password complexity", "Disk size"],
    correctAnswer: 0,
    explanation: "Lower MTTR means faster containment and resolution.",
  },
  {
    id: 63,
    topic: "Metrics",
    question: "A good severity matrix considers:",
    options: ["Impact and urgency", "Only number of alerts", "Only system age", "Only vendor type"],
    correctAnswer: 0,
    explanation: "Severity uses impact and urgency to prioritize response.",
  },
  {
    id: 64,
    topic: "Metrics",
    question: "An incident SLA should define:",
    options: ["Expected response times by severity", "Only backup schedules", "Only user training", "Only patch windows"],
    correctAnswer: 0,
    explanation: "SLAs guide response timing expectations.",
  },
  {
    id: 65,
    topic: "Metrics",
    question: "A common IR KPI is:",
    options: ["Time to containment", "Marketing reach", "Sales pipeline", "Printer uptime"],
    correctAnswer: 0,
    explanation: "Containment time measures response effectiveness.",
  },
  {
    id: 66,
    topic: "Governance",
    question: "IR playbooks are useful because they:",
    options: ["Provide consistent, repeatable actions", "Replace logging", "Eliminate training", "Disable monitoring"],
    correctAnswer: 0,
    explanation: "Playbooks standardize responses to common incidents.",
  },
  {
    id: 67,
    topic: "Governance",
    question: "Tabletop exercises help teams:",
    options: ["Practice response procedures safely", "Avoid documentation", "Ignore escalation", "Disable alerts"],
    correctAnswer: 0,
    explanation: "Exercises improve readiness without real incidents.",
  },
  {
    id: 68,
    topic: "Governance",
    question: "An IR policy should define:",
    options: ["Roles, responsibilities, and escalation paths", "Only tool versions", "Only passwords", "Only vendor names"],
    correctAnswer: 0,
    explanation: "Policy establishes how incidents are managed.",
  },
  {
    id: 69,
    topic: "Governance",
    question: "Why maintain a contact list?",
    options: ["To notify stakeholders quickly", "To store passwords", "To replace monitoring", "To avoid analysis"],
    correctAnswer: 0,
    explanation: "Contact lists enable quick coordination during incidents.",
  },
  {
    id: 70,
    topic: "Governance",
    question: "Legal counsel should be involved when:",
    options: ["Evidence handling or regulatory reporting is required", "Only for phishing", "Never", "Only for backups"],
    correctAnswer: 0,
    explanation: "Legal involvement protects the organization during investigations.",
  },
  {
    id: 71,
    topic: "Best Practices",
    question: "Why log in UTC?",
    options: ["It standardizes timelines across systems", "It hides activity", "It speeds up detection", "It reduces storage"],
    correctAnswer: 0,
    explanation: "UTC avoids time zone confusion in timelines.",
  },
  {
    id: 72,
    topic: "Best Practices",
    question: "A strong IR report should be:",
    options: ["Clear, evidence-based, and reproducible", "Opinion-based", "Only screenshots", "Only a list of IPs"],
    correctAnswer: 0,
    explanation: "Reports must be defensible and based on evidence.",
  },
  {
    id: 73,
    topic: "Best Practices",
    question: "Which action is unsafe during analysis?",
    options: ["Rebooting an infected host before capturing memory", "Capturing logs", "Creating an image", "Hashing evidence"],
    correctAnswer: 0,
    explanation: "Rebooting can destroy volatile evidence.",
  },
  {
    id: 74,
    topic: "Best Practices",
    question: "Why keep detailed timelines?",
    options: ["To correlate events and actions precisely", "To reduce alerts", "To remove evidence", "To avoid reporting"],
    correctAnswer: 0,
    explanation: "Timelines help reconstruct the incident accurately.",
  },
  {
    id: 75,
    topic: "Best Practices",
    question: "A key outcome of lessons learned is:",
    options: ["Updated controls and improved processes", "Deleting all evidence", "Reducing monitoring", "Ignoring findings"],
    correctAnswer: 0,
    explanation: "Lessons learned drive improvements to prevent recurrence.",
  },
];
// IR phases based on NIST framework
const irPhases = [
  {
    phase: "1. Preparation",
    icon: <ShieldIcon />,
    description: "Establish IR capability before incidents occur",
    color: "#3b82f6",
    objectives: [
      "Develop IR policies and procedures",
      "Build and train IR team",
      "Prepare tools and resources",
      "Establish communication channels",
      "Create incident documentation templates",
    ],
    keyActivities: [
      "Asset inventory and classification",
      "Baseline configuration documentation",
      "Deploy monitoring and detection tools",
      "Conduct tabletop exercises",
      "Establish legal and HR contacts",
    ],
    detailedSteps: [
      "Create and maintain an IR policy approved by senior management",
      "Define roles: IR Lead, Forensic Analyst, Communications, Legal Liaison",
      "Build jump bag with forensic tools, write blockers, and documentation",
      "Establish out-of-band communication (Signal, secure phone tree)",
      "Maintain updated contact lists for all stakeholders",
      "Schedule quarterly tabletop exercises and annual full simulations",
      "Document baseline configurations and golden images",
      "Pre-authorize forensic activities with legal counsel",
    ],
    commonMistakes: [
      "No executive sponsorship or budget",
      "Untested backup and recovery procedures",
      "Missing legal pre-authorization for forensic activities",
      "No out-of-band communication plan",
    ],
  },
  {
    phase: "2. Detection & Analysis",
    icon: <SearchIcon />,
    description: "Identify and investigate potential incidents",
    color: "#f59e0b",
    objectives: [
      "Monitor for security events",
      "Analyze alerts and anomalies",
      "Determine incident scope",
      "Document initial findings",
      "Assign severity and priority",
    ],
    keyActivities: [
      "SIEM alert triage",
      "Log correlation and analysis",
      "IOC identification",
      "Initial forensic preservation",
      "Stakeholder notification",
    ],
    detailedSteps: [
      "Validate the alert - eliminate false positives",
      "Determine if this is an incident, event, or false positive",
      "Identify affected systems, users, and data",
      "Establish initial timeline of events",
      "Collect and preserve volatile evidence (memory, running processes)",
      "Document everything with timestamps in UTC",
      "Assign incident severity based on impact and urgency",
      "Notify appropriate stakeholders per escalation matrix",
    ],
    commonMistakes: [
      "Alert fatigue leading to missed incidents",
      "Destroying evidence by rebooting systems",
      "Failing to preserve memory before disk imaging",
      "Not documenting with precise timestamps",
    ],
  },
  {
    phase: "3. Containment",
    icon: <WarningAmberIcon />,
    description: "Limit the damage and prevent further compromise",
    color: "#ef4444",
    objectives: [
      "Stop incident spread",
      "Preserve evidence",
      "Maintain business operations",
      "Short-term vs long-term strategy",
      "Document containment actions",
    ],
    keyActivities: [
      "Network isolation/segmentation",
      "Account disabling",
      "Firewall rule updates",
      "DNS sinkholing",
      "System imaging for forensics",
    ],
    detailedSteps: [
      "SHORT-TERM: Immediately isolate affected systems from network",
      "SHORT-TERM: Block malicious IPs/domains at firewall/proxy",
      "SHORT-TERM: Disable compromised accounts (preserve, don't delete)",
      "SHORT-TERM: Implement DNS sinkhole for C2 domains",
      "Create forensic images of affected systems",
      "LONG-TERM: Implement network segmentation",
      "LONG-TERM: Deploy additional monitoring on affected segments",
      "LONG-TERM: Patch identified vulnerabilities",
      "Document all containment actions with timestamps",
    ],
    commonMistakes: [
      "Alerting attacker by obvious containment actions",
      "Powering off systems before memory capture",
      "Deleting accounts instead of disabling them",
      "Not creating forensic images before cleanup",
    ],
  },
  {
    phase: "4. Eradication",
    icon: <BugReportIcon />,
    description: "Remove the threat from the environment",
    color: "#dc2626",
    objectives: [
      "Identify root cause",
      "Remove malware and artifacts",
      "Close attack vectors",
      "Patch vulnerabilities",
      "Verify complete removal",
    ],
    keyActivities: [
      "Malware removal and cleanup",
      "Password resets",
      "System rebuilds",
      "Vulnerability remediation",
      "Security control improvements",
    ],
    detailedSteps: [
      "Identify and document the root cause of the incident",
      "Remove all malware, backdoors, and persistence mechanisms",
      "Clean or rebuild affected systems from known-good images",
      "Reset passwords for all compromised and potentially compromised accounts",
      "Revoke and reissue certificates if compromised",
      "Patch vulnerabilities exploited in the attack",
      "Close attack vectors (disable unused services, ports)",
      "Verify eradication by scanning with multiple tools",
      "Hunt for additional indicators across the environment",
    ],
    commonMistakes: [
      "Missing persistence mechanisms (scheduled tasks, services)",
      "Not resetting service account passwords",
      "Incomplete malware removal leading to re-infection",
      "Not addressing root cause vulnerability",
    ],
  },
  {
    phase: "5. Recovery",
    icon: <RestoreIcon />,
    description: "Restore systems to normal operations",
    color: "#10b981",
    objectives: [
      "Restore systems from backups",
      "Rebuild compromised systems",
      "Validate system integrity",
      "Monitor for re-infection",
      "Return to normal operations",
    ],
    keyActivities: [
      "System restoration",
      "Data recovery",
      "Enhanced monitoring",
      "Phased return to production",
      "User communication",
    ],
    detailedSteps: [
      "Restore systems from clean backups (verify backup integrity first)",
      "Rebuild systems that cannot be trusted from golden images",
      "Apply all security patches before reconnecting to network",
      "Implement additional security controls identified during investigation",
      "Deploy enhanced monitoring on recovered systems",
      "Reconnect systems in phases, starting with least critical",
      "Monitor closely for signs of re-infection for 30-90 days",
      "Verify business functionality after restoration",
      "Communicate recovery status to stakeholders",
    ],
    commonMistakes: [
      "Restoring from compromised backups",
      "Not patching before reconnecting to network",
      "Returning to production too quickly",
      "Removing enhanced monitoring too soon",
    ],
  },
  {
    phase: "6. Lessons Learned",
    icon: <SchoolIcon />,
    description: "Improve future incident response",
    color: "#8b5cf6",
    objectives: [
      "Document incident timeline",
      "Identify what worked/didn't",
      "Update procedures",
      "Improve detection capabilities",
      "Share knowledge",
    ],
    keyActivities: [
      "Post-incident review meeting",
      "Timeline reconstruction",
      "Gap analysis",
      "Procedure updates",
      "Training improvements",
    ],
    detailedSteps: [
      "Schedule post-incident review within 2 weeks of closure",
      "Include all team members involved in the response",
      "Create final incident timeline with all events and actions",
      "Document what worked well during the response",
      "Document what could be improved",
      "Identify gaps in detection, response, or recovery",
      "Update IR procedures based on lessons learned",
      "Implement new detection rules for similar attacks",
      "Share sanitized findings with appropriate communities (ISACs)",
      "Provide additional training based on identified gaps",
    ],
    commonMistakes: [
      "Skipping lessons learned due to 'being too busy'",
      "Blame-focused instead of improvement-focused discussions",
      "Not implementing identified improvements",
      "Not sharing lessons with the broader security community",
    ],
  },
];

// Common incident types with expanded details
const incidentTypes = [
  {
    type: "Malware/Ransomware",
    icon: <BugReportIcon />,
    severity: "Critical",
    indicators: ["Encrypted files", "Ransom notes", "Unusual processes", "C2 traffic", "Mass file modifications", "Anti-forensics activity"],
    initialSteps: [
      "Isolate affected systems immediately",
      "Preserve memory dumps",
      "Identify ransomware variant",
      "Check for backups",
      "Contact legal/law enforcement",
    ],
    technicalIndicators: [
      "High CPU/disk I/O from unknown processes",
      "Files with new extensions (.encrypted, .locked, .crypted)",
      "Scheduled task or service persistence",
      "Registry Run key modifications",
      "Suspicious network connections to known C2",
      "Shadow copy deletion commands",
      "Disabled Windows Defender or security tools",
    ],
    investigationQueries: `# Check for ransomware indicators
Get-ChildItem -Path C:\\ -Include *.encrypted,*.locked,*.crypted -Recurse
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} | Where-Object {$_.Message -match 'vssadmin|bcdedit|wbadmin'}
Get-Process | Where-Object {$_.Path -notlike 'C:\\Windows\\*' -and $_.Path -notlike 'C:\\Program Files*'}`,
  },
  {
    type: "Phishing/BEC",
    icon: <EmailIcon />,
    severity: "High",
    indicators: ["Suspicious emails", "Credential harvesting", "Wire transfer requests", "Domain spoofing", "Mailbox rule creation", "OAuth app consent"],
    initialSteps: [
      "Block sender/domain",
      "Identify recipients",
      "Reset compromised credentials",
      "Check for forwarding rules",
      "Notify affected users",
    ],
    technicalIndicators: [
      "Login from unusual location/IP",
      "Inbox rules forwarding to external addresses",
      "OAuth application grants to unknown apps",
      "Multiple failed MFA attempts",
      "Password spray attack patterns",
      "Impersonation of executive accounts",
      "Urgent wire transfer requests",
    ],
    investigationQueries: `# Check for mailbox rules (Exchange/O365)
Get-InboxRule -Mailbox user@domain.com | Where-Object {$_.ForwardTo -or $_.RedirectTo}
# Check Azure AD sign-in logs
Search-UnifiedAuditLog -Operations UserLoggedIn -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
# Check OAuth app consents
Get-AzureADAuditSignInLogs | Where-Object {$_.AppDisplayName -like "*suspicious*"}`,
  },
  {
    type: "Data Breach",
    icon: <StorageIcon />,
    severity: "Critical",
    indicators: ["Unusual data access", "Large file transfers", "Database queries", "Exfiltration traffic", "Cloud storage uploads", "USB device usage"],
    initialSteps: [
      "Identify data accessed",
      "Determine exposure scope",
      "Preserve access logs",
      "Notify legal/compliance",
      "Prepare breach notification",
    ],
    technicalIndicators: [
      "Large outbound data transfers",
      "Access to sensitive files by unusual users",
      "Database export or dump queries",
      "Cloud sync to personal accounts",
      "Compression of large file sets",
      "After-hours data access",
      "Bulk file downloads from SharePoint/OneDrive",
    ],
    investigationQueries: `# Check for large file transfers
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145} | Where-Object {$_.Message -match 'sensitive'}
# Network traffic analysis
netstat -an | findstr ESTABLISHED | findstr :443
# Cloud access logs (Azure)
Search-UnifiedAuditLog -Operations FileDownloaded,FileSyncDownloadedFull -StartDate (Get-Date).AddDays(-7)`,
  },
  {
    type: "Insider Threat",
    icon: <GroupIcon />,
    severity: "High",
    indicators: ["Unusual access patterns", "After-hours activity", "Mass downloads", "Policy violations", "Resignation + data access", "Privilege abuse"],
    initialSteps: [
      "Coordinate with HR/Legal",
      "Preserve all evidence",
      "Review access logs",
      "Monitor without alerting",
      "Document chain of custody",
    ],
    technicalIndicators: [
      "Access to files outside normal job function",
      "USB device connections on sensitive systems",
      "Personal cloud storage uploads",
      "Email to personal addresses with attachments",
      "Screenshot or screen recording activity",
      "Privilege escalation attempts",
      "Badge access anomalies",
    ],
    investigationQueries: `# Check user file access patterns
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 1000 | Where-Object {$_.Message -match 'username'}
# USB device connections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational';ID=2003}
# After-hours activity
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} | Where-Object {$_.TimeCreated.Hour -lt 6 -or $_.TimeCreated.Hour -gt 22}`,
  },
  {
    type: "DDoS Attack",
    icon: <CloudIcon />,
    severity: "Medium-High",
    indicators: ["Service degradation", "Traffic spikes", "Resource exhaustion", "Multiple source IPs", "Application errors", "Timeout increases"],
    initialSteps: [
      "Engage DDoS mitigation",
      "Analyze traffic patterns",
      "Implement rate limiting",
      "Contact ISP/CDN",
      "Preserve traffic logs",
    ],
    technicalIndicators: [
      "Sudden spike in requests per second",
      "High bandwidth utilization",
      "Connection table exhaustion",
      "SYN flood patterns",
      "UDP amplification traffic",
      "Application layer attacks (HTTP floods)",
      "Geographic distribution of attack sources",
    ],
    investigationQueries: `# Network traffic analysis
tcpdump -i eth0 -c 10000 -w ddos_capture.pcap
# Connection analysis
netstat -an | awk '/tcp/ {print $6}' | sort | uniq -c | sort -rn
# Top talkers
iptables -L -n -v | head -20`,
  },
  {
    type: "Unauthorized Access",
    icon: <LockIcon />,
    severity: "High",
    indicators: ["Failed logins", "New accounts", "Privilege escalation", "Unusual login locations", "Pass-the-hash", "Kerberoasting"],
    initialSteps: [
      "Disable compromised accounts",
      "Review authentication logs",
      "Check for persistence",
      "Audit privilege changes",
      "Enable additional monitoring",
    ],
    technicalIndicators: [
      "Event ID 4625 - Failed logon attempts",
      "Event ID 4768/4769 - Kerberos ticket requests",
      "Event ID 4672 - Special privileges assigned",
      "Event ID 4720 - User account created",
      "Event ID 4732 - Member added to security-enabled group",
      "NTLM authentication from unexpected sources",
      "Service account interactive logons",
    ],
    investigationQueries: `# Check failed logins
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 100
# Check new accounts
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4720} -MaxEvents 50
# Check privilege escalation
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4672,4673,4674} -MaxEvents 100
# Check group membership changes
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4728,4732,4756} -MaxEvents 50`,
  },
  {
    type: "Supply Chain Attack",
    icon: <NetworkCheckIcon />,
    severity: "Critical",
    indicators: ["Compromised updates", "Malicious packages", "Third-party breach", "Trusted code signing", "Build system compromise", "Dependency confusion"],
    initialSteps: [
      "Identify affected software/versions",
      "Inventory all installations",
      "Block update mechanisms",
      "Contact vendor for IOCs",
      "Hunt for indicators across environment",
    ],
    technicalIndicators: [
      "Unexpected software behavior after update",
      "Network connections from trusted applications",
      "Code signing certificate anomalies",
      "Modified installation packages",
      "Suspicious build artifacts",
      "Unknown dependencies in projects",
    ],
    investigationQueries: `# Check installed software versions
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
# Verify code signatures
Get-AuthenticodeSignature -FilePath "C:\\Program Files\\*\\*.exe" | Where-Object {$_.Status -ne 'Valid'}
# Check for suspicious npm/pip packages
npm audit
pip-audit`,
  },
  {
    type: "Cryptojacking",
    icon: <SpeedIcon />,
    severity: "Medium",
    indicators: ["High CPU usage", "Mining pool connections", "Unexpected processes", "Performance degradation", "Increased electricity costs", "Browser-based mining"],
    initialSteps: [
      "Identify mining processes",
      "Block mining pool domains",
      "Remove malicious software",
      "Check for persistence",
      "Patch exploitation vector",
    ],
    technicalIndicators: [
      "Sustained high CPU usage (>80%)",
      "Connections to mining pools (port 3333, 4444, 8333)",
      "Processes with names like xmrig, minerd, cpuminer",
      "Browser processes with high CPU",
      "Cron jobs or scheduled tasks running miners",
      "Docker containers running mining software",
    ],
    investigationQueries: `# Check CPU usage by process
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
# Check for mining pool connections
netstat -an | findstr "3333 4444 8333 14444"
# Check scheduled tasks
schtasks /query /fo LIST /v | findstr /i "mine xmr crypto"`,
  },
];

// Essential IR tools with expanded details
const irTools = [
  { name: "Velociraptor", category: "Collection", description: "Endpoint visibility and collection at scale", url: "https://velociraptor.app", usage: "velociraptor gui", platform: "Cross-platform" },
  { name: "KAPE", category: "Collection", description: "Kroll Artifact Parser and Extractor for Windows triage", url: "https://www.kroll.com/kape", usage: "kape.exe --tsource C: --tdest D:\\Evidence --target !SANS_Triage", platform: "Windows" },
  { name: "Volatility 3", category: "Memory", description: "Memory forensics framework for RAM analysis", url: "https://volatilityfoundation.org", usage: "vol -f memory.raw windows.pslist", platform: "Cross-platform" },
  { name: "Plaso/log2timeline", category: "Timeline", description: "Super timeline creation from multiple sources", url: "https://plaso.readthedocs.io", usage: "log2timeline.py timeline.plaso image.E01", platform: "Cross-platform" },
  { name: "Elastic SIEM", category: "Detection", description: "SIEM and security analytics with ELK stack", url: "https://elastic.co/security", usage: "Web UI / Kibana", platform: "Cross-platform" },
  { name: "TheHive", category: "Case Mgmt", description: "Security incident response platform with case management", url: "https://thehive-project.org", usage: "Web UI", platform: "Cross-platform" },
  { name: "MISP", category: "Threat Intel", description: "Malware information sharing platform for IOCs", url: "https://misp-project.org", usage: "Web UI / API", platform: "Cross-platform" },
  { name: "Cortex", category: "Analysis", description: "Observable analysis and active response automation", url: "https://thehive-project.org", usage: "API integration with TheHive", platform: "Cross-platform" },
  { name: "Chainsaw", category: "Log Analysis", description: "Fast Windows event log analysis with Sigma rules", url: "https://github.com/WithSecureLabs/chainsaw", usage: "chainsaw hunt evtx_files/ -s sigma/ --mapping mapping.yml", platform: "Cross-platform" },
  { name: "Hayabusa", category: "Log Analysis", description: "Windows event log fast forensics timeline generator", url: "https://github.com/Yamato-Security/hayabusa", usage: "hayabusa csv-timeline -d ./logs -o timeline.csv", platform: "Cross-platform" },
  { name: "Eric Zimmerman Tools", category: "Forensics", description: "Suite of Windows forensic tools (MFTECmd, Registry Explorer, etc.)", url: "https://ericzimmerman.github.io", usage: "Various CLI tools", platform: "Windows" },
  { name: "Autopsy", category: "Forensics", description: "Digital forensics platform with GUI", url: "https://sleuthkit.org/autopsy", usage: "GUI-based", platform: "Cross-platform" },
  { name: "FTK Imager", category: "Collection", description: "Forensic imaging tool for disk acquisition", url: "https://www.exterro.com/ftk-imager", usage: "GUI-based imaging", platform: "Windows" },
  { name: "Arsenal Image Mounter", category: "Forensics", description: "Mount forensic images as drives", url: "https://arsenalrecon.com", usage: "GUI for mounting E01, raw images", platform: "Windows" },
  { name: "CyberChef", category: "Analysis", description: "Web-based data transformation and encoding tool", url: "https://gchq.github.io/CyberChef", usage: "Web UI for decoding, deobfuscation", platform: "Web" },
  { name: "YARA", category: "Detection", description: "Pattern matching for malware identification", url: "https://virustotal.github.io/yara", usage: "yara -r rules.yar /path/to/scan", platform: "Cross-platform" },
];

// Windows Event IDs for detection
const windowsEventIds = [
  { id: "4624", category: "Logon", description: "Successful logon", importance: "Track user access" },
  { id: "4625", category: "Logon", description: "Failed logon attempt", importance: "Detect brute force, password spray" },
  { id: "4648", category: "Logon", description: "Explicit credentials used", importance: "Lateral movement detection" },
  { id: "4672", category: "Privilege", description: "Special privileges assigned", importance: "Admin activity tracking" },
  { id: "4688", category: "Process", description: "Process creation", importance: "Command line logging" },
  { id: "4689", category: "Process", description: "Process termination", importance: "Process lifecycle" },
  { id: "4697", category: "Service", description: "Service installed", importance: "Persistence detection" },
  { id: "4698", category: "Scheduled Task", description: "Scheduled task created", importance: "Persistence detection" },
  { id: "4720", category: "Account", description: "User account created", importance: "Unauthorized accounts" },
  { id: "4732", category: "Group", description: "Member added to security group", importance: "Privilege escalation" },
  { id: "4768", category: "Kerberos", description: "TGT requested", importance: "Authentication tracking" },
  { id: "4769", category: "Kerberos", description: "Service ticket requested", importance: "Kerberoasting detection" },
  { id: "4771", category: "Kerberos", description: "Kerberos pre-auth failed", importance: "AS-REP roasting" },
  { id: "5140", category: "Share", description: "Network share accessed", importance: "Lateral movement" },
  { id: "5145", category: "Share", description: "Share object access checked", importance: "Data access tracking" },
  { id: "7045", category: "Service", description: "Service installed (System log)", importance: "Persistence detection" },
];

// Sigma rule examples
const sigmaRules = [
  {
    name: "Suspicious PowerShell Download",
    description: "Detects PowerShell download cradles often used by malware",
    rule: `title: Suspicious PowerShell Download Cradle
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'downloadstring'
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
            - 'Invoke-WebRequest'
    condition: selection
level: high`,
  },
  {
    name: "LSASS Memory Access",
    description: "Detects potential credential dumping via LSASS access",
    rule: `title: LSASS Memory Access for Credential Dumping
status: stable
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1410'
            - '0x143a'
    filter:
        SourceImage|endswith:
            - '\\wmiprvse.exe'
            - '\\taskmgr.exe'
    condition: selection and not filter
level: critical`,
  },
  {
    name: "Scheduled Task Creation",
    description: "Detects scheduled task creation for persistence",
    rule: `title: Suspicious Scheduled Task Creation
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    filter:
        TaskContent|contains:
            - 'Microsoft'
            - 'Adobe'
            - 'Google'
    condition: selection and not filter
level: medium`,
  },
  {
    name: "Mimikatz Command Line",
    description: "Detects Mimikatz usage patterns",
    rule: `title: Mimikatz Command Line Arguments
status: stable
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'kerberos::'
            - 'crypto::'
            - 'lsadump::'
            - 'privilege::debug'
            - 'token::elevate'
    condition: selection
level: critical`,
  },
];

// Severity levels with expanded criteria
const severityLevels = [
  {
    level: "Critical (P1)",
    color: "#dc2626",
    criteria: "Active breach, ransomware, critical system compromise",
    response: "Immediate - All hands on deck",
    sla: "15 minutes",
    examples: [
      "Active ransomware encryption in progress",
      "Confirmed data exfiltration of PII/PHI",
      "Domain controller compromise",
      "CEO/CFO account compromise (BEC)",
      "Production database breach",
    ],
    escalation: "CIO/CISO, Legal, Executive Team, External IR if needed",
  },
  {
    level: "High (P2)",
    color: "#f59e0b",
    criteria: "Confirmed malware, data exposure, credential compromise",
    response: "Within 1 hour",
    sla: "1 hour",
    examples: [
      "Confirmed malware on endpoint",
      "Compromised user credentials",
      "Phishing with confirmed clicks",
      "Unauthorized access to sensitive system",
      "Security tool bypass detected",
    ],
    escalation: "Security Manager, IT Director, Department Heads as needed",
  },
  {
    level: "Medium (P3)",
    color: "#3b82f6",
    criteria: "Suspicious activity, policy violation, potential threat",
    response: "Within 4 hours",
    sla: "4 hours",
    examples: [
      "Suspicious login patterns",
      "Policy violation alerts",
      "Potentially unwanted software",
      "Failed intrusion attempts",
      "Anomalous network traffic",
    ],
    escalation: "Security Team Lead, System Administrators",
  },
  {
    level: "Low (P4)",
    color: "#10b981",
    criteria: "Minor security event, false positive investigation",
    response: "Within 24 hours",
    sla: "24 hours",
    examples: [
      "Routine security alerts",
      "False positive investigation",
      "Minor policy violations",
      "Information requests",
      "Vulnerability scan results",
    ],
    escalation: "Security Analyst",
  },
];

// Documentation templates with expanded details
const documentationTemplates = [
  { name: "Incident Ticket", purpose: "Initial incident record", fields: "Date, time, reporter, description, severity, affected systems", critical: true },
  { name: "Evidence Log", purpose: "Chain of custody tracking", fields: "Evidence ID, description, collector, date/time, storage location, hash", critical: true },
  { name: "Timeline", purpose: "Chronological event sequence", fields: "Timestamp, source, event description, actor, impact", critical: true },
  { name: "Communication Log", purpose: "Stakeholder communications", fields: "Date/time, parties, method, summary, action items", critical: false },
  { name: "Post-Incident Report", purpose: "Final incident summary", fields: "Executive summary, timeline, impact, root cause, recommendations", critical: true },
  { name: "IOC List", purpose: "Indicators of compromise tracking", fields: "Type, value, context, first seen, source, confidence", critical: true },
  { name: "Containment Actions", purpose: "Track containment steps", fields: "Action, system, time, performed by, result, reversible", critical: false },
  { name: "Recovery Checklist", purpose: "System restoration tracking", fields: "System, backup date, restore date, verified by, status", critical: false },
];

// Key metrics with industry benchmarks
const irMetrics = [
  { metric: "MTTD", name: "Mean Time to Detect", description: "Average time from incident occurrence to detection", target: "< 24 hours", industry: "197 days (IBM 2023)" },
  { metric: "MTTR", name: "Mean Time to Respond", description: "Average time from detection to initial response", target: "< 1 hour", industry: "Varies by severity" },
  { metric: "MTTC", name: "Mean Time to Contain", description: "Average time from response to containment", target: "< 4 hours", industry: "70 days (IBM 2023)" },
  { metric: "MTTRE", name: "Mean Time to Recover", description: "Average time from containment to full recovery", target: "< 72 hours", industry: "Varies significantly" },
  { metric: "FPR", name: "False Positive Rate", description: "Percentage of alerts that are false positives", target: "< 20%", industry: "40-60% typical" },
  { metric: "COST", name: "Cost per Incident", description: "Average cost to respond to an incident", target: "Minimize", industry: "$4.45M breach (IBM 2023)" },
];

// IR readiness and coordination
const readinessChecklist = [
  "IR policy approved and reviewed annually",
  "On-call rotation and escalation contacts tested",
  "Forensic tools validated and licensed",
  "Centralized logging with time sync (NTP)",
  "Backups tested and restoration drills completed",
  "Runbooks for top incident types",
];

const stakeholderMatrix = [
  { stakeholder: "IR Lead", when: "All incidents", purpose: "Coordination and decision making" },
  { stakeholder: "Legal/Privacy", when: "Data exposure or regulatory scope", purpose: "Notification and evidence handling" },
  { stakeholder: "IT/Operations", when: "Containment or recovery required", purpose: "System actions and restoration" },
  { stakeholder: "HR", when: "Insider or employee actions", purpose: "Employee coordination and policy" },
  { stakeholder: "Comms/PR", when: "Customer or public impact", purpose: "External messaging and brand protection" },
  { stakeholder: "Executives", when: "High/critical severity", purpose: "Business risk and approvals" },
];

const evidenceHandlingChecklist = [
  "Capture volatile data before shutdown",
  "Hash evidence on collection and transfer",
  "Use write blockers for disk imaging",
  "Store evidence in access-controlled location",
  "Maintain chain of custody log",
];

const containmentDecisionFactors = [
  "Business impact vs. attacker awareness risk",
  "Propagation speed and blast radius",
  "Evidence preservation requirements",
  "Availability requirements for critical systems",
  "Regulatory notification timelines",
];

const commsCadence = [
  "Critical: updates every 2-4 hours",
  "High: daily updates or major milestones",
  "Medium: milestone-based updates",
  "Low: weekly or closure updates",
];

// Communication templates
const communicationTemplates = [
  {
    name: "Initial Stakeholder Notification",
    audience: "Internal stakeholders",
    template: `SECURITY INCIDENT NOTIFICATION

Incident ID: [INC-XXXX]
Time Detected: [YYYY-MM-DD HH:MM UTC]
Severity: [Critical/High/Medium/Low]

SUMMARY
We have detected a security incident affecting [systems/data]. 
Our incident response team is actively investigating.

CURRENT STATUS
- Detection: Complete
- Containment: In Progress
- Impact Assessment: Ongoing

NEXT UPDATE
Expected: [Time] or sooner if significant developments

ACTIONS REQUIRED
[List any actions stakeholders need to take]

Contact: [IR Lead Name] - [Phone/Email]`,
  },
  {
    name: "Executive Briefing",
    audience: "Executive leadership",
    template: `EXECUTIVE BRIEFING - SECURITY INCIDENT

Date: [Date]
Incident: [Brief description]
Business Impact: [High/Medium/Low]
Estimated Cost: [If known]

KEY FACTS
• What happened: [1-2 sentences]
• Systems affected: [List]
• Data at risk: [Type and volume]
• Current status: [Contained/Active/Resolved]

RESPONSE ACTIONS
1. [Action taken]
2. [Action taken]
3. [Planned action]

TIMELINE TO RESOLUTION
Estimated: [Hours/Days]

DECISIONS NEEDED
• [Any executive decisions required]

NEXT BRIEFING: [Date/Time]`,
  },
  {
    name: "Customer Breach Notification",
    audience: "Affected customers",
    template: `IMPORTANT SECURITY NOTICE

Dear [Customer],

We are writing to inform you of a security incident that may have affected your personal information.

WHAT HAPPENED
[Brief, clear description of the incident]

WHAT INFORMATION WAS INVOLVED
[Types of data potentially affected]

WHAT WE ARE DOING
[Steps being taken to address the incident]

WHAT YOU CAN DO
[Recommended actions for the customer]

FOR MORE INFORMATION
[Contact details, FAQ link, etc.]

We sincerely apologize for any inconvenience.

[Company Name]`,
  },
];

// Regulatory requirements
const regulatoryRequirements = [
  { regulation: "GDPR", requirement: "72-hour notification to supervisory authority", scope: "EU personal data", penalty: "Up to €20M or 4% annual revenue" },
  { regulation: "HIPAA", requirement: "60-day notification for breaches >500 records", scope: "Protected Health Information", penalty: "Up to $1.9M per violation category" },
  { regulation: "PCI DSS", requirement: "Immediate notification to card brands", scope: "Cardholder data", penalty: "Fines, increased transaction fees, loss of processing" },
  { regulation: "SOX", requirement: "Material incident disclosure", scope: "Public companies", penalty: "Fines, personal liability for executives" },
  { regulation: "CCPA/CPRA", requirement: "Notification without unreasonable delay", scope: "California residents' data", penalty: "Up to $7,500 per intentional violation" },
  { regulation: "NIS2 (EU)", requirement: "24-hour early warning, 72-hour full notification", scope: "Essential/important entities", penalty: "Up to €10M or 2% annual revenue" },
  { regulation: "SEC Rules", requirement: "4 business days for material incidents", scope: "Public companies (US)", penalty: "SEC enforcement actions" },
];

export default function IncidentResponseGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeSection, setActiveSection] = useState("intro");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Scroll to section handler
  const scrollToSection = (sectionId: string) => {
    setActiveSection(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    if (isMobile) setMobileNavOpen(false);
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => document.getElementById(item.id));
      const scrollPosition = window.scrollY + 100;

      for (let i = sections.length - 1; i >= 0; i--) {
        const section = sections[i];
        if (section && section.offsetTop <= scrollPosition) {
          setActiveSection(sectionNavItems[i].id);
          break;
        }
      }
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Sidebar navigation component
  const sidebarNav = (
    <List sx={{ p: 0 }}>
      {sectionNavItems.map((item) => {
        const Icon = item.icon;
        const isActive = activeSection === item.id;
        return (
          <ListItem
            key={item.id}
            onClick={() => scrollToSection(item.id)}
            sx={{
              cursor: "pointer",
              borderRadius: 2,
              mb: 0.5,
              bgcolor: isActive ? alpha(themeColors.primary, 0.1) : "transparent",
              borderLeft: isActive ? `3px solid ${themeColors.primary}` : "3px solid transparent",
              "&:hover": { bgcolor: alpha(themeColors.primary, 0.05) },
              transition: "all 0.2s ease",
            }}
          >
            <ListItemIcon sx={{ minWidth: 36 }}>
              <Icon sx={{ fontSize: 18, color: isActive ? themeColors.primary : themeColors.textMuted }} />
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                fontSize: "0.85rem",
                fontWeight: isActive ? 700 : 500,
                color: isActive ? themeColors.primary : themeColors.textMuted,
              }}
            />
          </ListItem>
        );
      })}
    </List>
  );

  const CodeBlock = ({ children }: { children: string }) => (
    <Paper
      sx={{
        p: 2,
        bgcolor: alpha(theme.palette.common.black, 0.8),
        borderRadius: 2,
        overflow: "auto",
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
      }}
    >
      <Typography
        component="pre"
        sx={{
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
          m: 0,
        }}
      >
        {children}
      </Typography>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Incident Response Guide" pageContext={pageContext}>
      <Container maxWidth="xl" sx={{ py: 4 }}>
        <Grid container spacing={3}>
          {/* Sidebar Navigation */}
          <Grid
            item
            md={2.5}
            sx={{
              display: { xs: "none", md: "block" },
              position: "sticky",
              top: 80,
              alignSelf: "flex-start",
              maxHeight: "calc(100vh - 100px)",
              overflowY: "auto",
            }}
          >
            <Paper
              elevation={0}
              sx={{
                p: 2,
                bgcolor: themeColors.bgCard,
                borderRadius: 3,
                border: `1px solid ${themeColors.border}`,
              }}
            >
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                Navigation
              </Typography>
              {sidebarNav}
            </Paper>
          </Grid>

          {/* Main Content */}
          <Grid item xs={12} md={9.5}>
            {/* Introduction Section */}
            <Box id="intro" sx={{ scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                {/* Back Link */}
                <Chip
                  component={Link}
                  to="/learn"
                  icon={<ArrowBackIcon />}
                  label="Back to Learning Hub"
                  clickable
                  variant="outlined"
                  sx={{ borderRadius: 2, mb: 3, borderColor: themeColors.border }}
                />

                {/* Header */}
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                  <Box
                    sx={{
                      width: 64,
                      height: 64,
                      borderRadius: 3,
                      bgcolor: alpha(themeColors.primary, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <SecurityIcon sx={{ fontSize: 36, color: themeColors.primary }} />
                  </Box>
                  <Box>
                    <Typography
                      variant="h4"
                      sx={{
                        fontWeight: 800,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      Incident Response Guide
                    </Typography>
                    <Typography variant="body1" sx={{ color: themeColors.textMuted }}>
                      NIST-based framework for detecting, responding to, and recovering from security incidents
                    </Typography>
                  </Box>
                </Box>

                {/* Tags */}
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                  {["NIST", "DFIR", "Playbooks", "Forensics", "Detection", "Recovery"].map((tag) => (
                    <Chip
                      key={tag}
                      label={tag}
                      size="small"
                      sx={{
                        bgcolor: alpha(themeColors.primary, 0.1),
                        color: themeColors.primary,
                        fontWeight: 600,
                      }}
                    />
                  ))}
                </Box>

                {/* What You'll Learn */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    📚 What You'll Learn
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      "NIST IR framework phases and best practices",
                      "How to handle different incident types (ransomware, phishing, breaches)",
                      "Response playbooks and step-by-step procedures",
                      "Detection techniques and Windows Event IDs",
                      "Essential IR tools and forensic collection methods",
                      "Documentation requirements and regulatory compliance",
                    ].map((item, idx) => (
                      <Grid item xs={12} sm={6} key={idx}>
                        <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                          <CheckCircleIcon sx={{ fontSize: 18, color: themeColors.primary, mt: 0.3 }} />
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{item}</Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    🧭 Beginner Lesson: The First 24 Hours Matter Most
                  </Typography>
                  <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                    Incident response is a race against time and uncertainty. In the first hours, you rarely know the full
                    scope of the incident. Your job is to stabilize the situation, preserve evidence, and prevent the attacker
                    from spreading. Think of it like triage in a hospital: stop the bleeding first, then diagnose and treat.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Beginners often want to immediately remove malware or wipe systems. That can destroy evidence and make
                    root-cause analysis impossible. The safer order is: identify, contain, preserve, then eradicate. If you
                    need to take a system offline, document the reason and capture volatile data first whenever possible.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                    A good habit is to keep an incident log from minute one with UTC timestamps, actions taken, and who
                    approved them. This log becomes the backbone of your final report.
                  </Typography>
                </Paper>
              </Paper>
            </Box>

            {/* Overview Section */}
            <Box id="overview" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <SecurityIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      🎯 Overview & Quick Reference
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                {/* Quick Reference Cards */}
                <Grid container spacing={2} sx={{ mb: 4 }}>
                  <Grid item xs={12} md={4}>
                    <Card sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <AccessTimeIcon sx={{ color: "#3b82f6" }} />
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Golden Hour</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                        The first 60 minutes are critical. Focus on evidence preservation and containment before cleanup.
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card sx={{ p: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <MemoryIcon sx={{ color: "#ef4444" }} />
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Volatility Order</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                        Collect volatile evidence first: Memory → Network state → Running processes → Disk
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Card sx={{ p: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <ArticleIcon sx={{ color: "#10b981" }} />
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Document Everything</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                        If it's not documented, it didn't happen. Use UTC timestamps for all records.
                      </Typography>
                    </Card>
                  </Grid>
                </Grid>

                <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    🧠 Incident Response Mindset for Beginners
                  </Typography>
                  <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                    Incident response is not just a technical task. It is a coordinated business process that protects
                    operations, customers, and reputation. You must balance speed with accuracy. Move too slowly and
                    attackers spread; move too fast and you may destroy evidence or disrupt critical systems.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                    Always ask three questions: What is happening? What systems are at risk? What evidence do we need
                    to preserve? These questions guide your priorities when information is incomplete.
                  </Typography>
                </Paper>

                {/* Key Metrics */}
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primaryLight }}>📊 Key IR Metrics & Benchmarks</Typography>
                <Grid container spacing={2}>
                  {irMetrics.map((m) => (
                    <Grid item xs={12} sm={6} md={4} key={m.metric}>
                      <Card sx={{ p: 2, textAlign: "center", bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, height: "100%" }}>
                        <Typography variant="h5" sx={{ fontWeight: 800, color: themeColors.primary }}>
                          {m.metric}
                        </Typography>
                        <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                          {m.name}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted, display: "block" }}>
                          {m.description}
                        </Typography>
                        <Divider sx={{ my: 1 }} />
                        <Typography variant="body2" sx={{ color: "#10b981", fontWeight: 600 }}>
                          Target: {m.target}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          Industry avg: {m.industry}
                        </Typography>
                      </Card>
                    </Grid>
                  ))}
                </Grid>

                <Paper sx={{ p: 3, mt: 4, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    First 72 Hours: Practical Timeline
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    This timeline gives beginners a realistic structure for the first three days of an incident. Use it as
                    a guide, not a rigid schedule. Large incidents may stretch these windows, but the priorities remain similar.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Time Window</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Primary Goals</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Typical Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          {
                            window: "0-4 hours",
                            goals: "Contain spread, preserve evidence, establish command",
                            actions: "Isolate hosts, capture memory, notify leadership, start incident log",
                          },
                          {
                            window: "4-24 hours",
                            goals: "Scope impact, confirm access paths, collect key artifacts",
                            actions: "Build timeline, identify affected systems, collect logs, validate backups",
                          },
                          {
                            window: "24-72 hours",
                            goals: "Eradicate, recover services, prepare initial report",
                            actions: "Remove persistence, reset credentials, restore services, brief stakeholders",
                          },
                        ].map((row) => (
                          <TableRow key={row.window}>
                            <TableCell>{row.window}</TableCell>
                            <TableCell>{row.goals}</TableCell>
                            <TableCell>{row.actions}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Paper>
            </Box>

            {/* IR Phases Section */}
            <Box id="ir-phases" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <TimelineIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      📋 NIST Incident Response Phases
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>NIST Incident Response Framework (SP 800-61 Rev. 2)</AlertTitle>
                  The NIST framework provides a structured approach to handling security incidents through six phases. 
                  Each phase builds on the previous and may require iteration as new information is discovered.
                </Alert>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Beginners often assume the phases are strictly linear. In reality, you frequently loop back. For example,
                  while containing an incident you may discover new systems affected, which pushes you back into detection
                  and analysis. Treat the phases as a guide for priorities, not a rigid checklist.
                </Typography>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Beginner Walkthrough: How the Phases Look in Real Life
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Example scenario: an alert shows a suspicious login from a new country. You start in Detection & Analysis,
                    confirm the login is real, then move to Containment by disabling the account. While doing so, you discover
                    a mailbox forwarding rule (back to Detection & Analysis). After containment, you reset passwords and remove
                    persistence (Eradication), then restore normal access (Recovery). Finally, you run a Lessons Learned review
                    to update MFA policies and detection rules.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                    This flow shows why phases overlap. The goal is not perfect order, but consistent priorities and clear
                    documentation.
                  </Typography>
                </Paper>

                {irPhases.map((phase, idx) => (
                  <Accordion key={idx} defaultExpanded={idx === 0} sx={{ mb: 1, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                        <Box
                          sx={{
                            width: 48,
                            height: 48,
                            borderRadius: 2,
                            bgcolor: alpha(phase.color, 0.1),
                            color: phase.color,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                          }}
                        >
                          {phase.icon}
                        </Box>
                        <Box>
                          <Typography variant="h6" sx={{ fontWeight: 700, color: phase.color }}>
                            {phase.phase}
                          </Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                      {phase.description}
                    </Typography>
                  </Box>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Objectives
                    </Typography>
                    <List dense>
                      {phase.objectives.map((obj, i) => (
                        <ListItem key={i} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: phase.color }} />
                          </ListItemIcon>
                          <ListItemText primary={obj} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Key Activities
                    </Typography>
                    <List dense>
                      {phase.keyActivities.map((act, i) => (
                        <ListItem key={i} sx={{ py: 0.5 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <PlayArrowIcon sx={{ fontSize: 16, color: "text.secondary" }} />
                          </ListItemIcon>
                          <ListItemText primary={act} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                  <Grid item xs={12}>
                    <Divider sx={{ my: 1 }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Detailed Steps
                    </Typography>
                    <Stepper orientation="vertical" sx={{ mt: 1 }}>
                      {phase.detailedSteps?.map((step, i) => (
                        <Step key={i} active>
                          <StepLabel>
                            <Typography variant="body2">{step}</Typography>
                          </StepLabel>
                        </Step>
                      ))}
                    </Stepper>
                  </Grid>
                  <Grid item xs={12}>
                    <Alert severity="warning" sx={{ mt: 1 }}>
                      <AlertTitle>Common Mistakes to Avoid</AlertTitle>
                      <List dense>
                        {phase.commonMistakes?.map((mistake, i) => (
                          <ListItem key={i} sx={{ py: 0 }}>
                            <ListItemIcon sx={{ minWidth: 24 }}>
                              <CancelIcon sx={{ fontSize: 14, color: "warning.main" }} />
                            </ListItemIcon>
                            <ListItemText primary={mistake} primaryTypographyProps={{ variant: "body2" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Alert>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}

                {/* Severity Levels */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Incident Severity Classification
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Proper severity classification ensures appropriate resource allocation and response times.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Severity is about business impact, not just technical impact. A malware infection on a lab machine is
                    lower severity than a credential theft on a finance server. Use severity to decide who must be notified
                    and how fast response actions must happen.
                  </Typography>
                  {severityLevels.map((sev) => (
                    <Accordion key={sev.level} sx={{ mb: 1, bgcolor: themeColors.bgCard, "&:before": { display: "none" } }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <Chip label={sev.level} size="small" sx={{ bgcolor: alpha(sev.color, 0.1), color: sev.color, fontWeight: 700, minWidth: 100 }} />
                          <Typography variant="body2" sx={{ flex: 1 }}>{sev.criteria}</Typography>
                          <Chip label={`SLA: ${sev.sla}`} size="small" variant="outlined" />
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Examples</Typography>
                            <List dense>
                              {sev.examples?.map((ex, i) => (
                                <ListItem key={i} sx={{ py: 0.25 }}>
                                  <ListItemIcon sx={{ minWidth: 20 }}>
                                    <Box sx={{ width: 6, height: 6, borderRadius: "50%", bgcolor: sev.color }} />
                                  </ListItemIcon>
                                  <ListItemText primary={ex} primaryTypographyProps={{ variant: "body2" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Escalation</Typography>
                            <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{sev.escalation}</Typography>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Paper>

                {/* IR Readiness Checklist */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: themeColors.primary }}>
                    <ShieldIcon sx={{ color: themeColors.primary }} /> IR Readiness Checklist
                  </Typography>
                  <List dense>
                    {readinessChecklist.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                    Readiness is the difference between panic and control. If you already know who to call, where logs are
                    stored, and how to isolate systems, you can act quickly without improvising. Treat readiness as a living
                    program: update it after every incident and exercise it regularly.
                  </Typography>
                </Paper>

                {/* Stakeholder Matrix */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: themeColors.primary }}>
                    <GroupIcon sx={{ color: themeColors.primary }} /> Stakeholder Notification Matrix
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Stakeholder</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>When to Notify</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {stakeholderMatrix.map((row) => (
                          <TableRow key={row.stakeholder}>
                            <TableCell sx={{ fontWeight: 600 }}>{row.stakeholder}</TableCell>
                            <TableCell>{row.when}</TableCell>
                            <TableCell>{row.purpose}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>

                {/* Evidence Handling */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: themeColors.primary }}>
                    <FolderIcon sx={{ color: themeColors.primary }} /> Evidence Handling Quick Checklist
                  </Typography>
                  <List dense>
                    {evidenceHandlingChecklist.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                    Evidence handling is about trust. If you cannot prove evidence was protected from tampering, it may be
                    inadmissible in court or useless for regulatory audits. Beginners should always capture hashes at the
                    time of collection and store evidence in a controlled location with access logs.
                  </Typography>
                </Paper>

                {/* Containment Decision Factors */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: themeColors.primary }}>
                    <PolicyIcon sx={{ color: themeColors.primary }} /> Containment Decision Factors
                  </Typography>
                  <List dense>
                    {containmentDecisionFactors.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                    Containment is a business decision as much as a technical one. Disconnecting a critical server may stop
                    an attacker but also halt operations. When in doubt, consider partial containment (blocking outbound
                    traffic, disabling accounts) before full shutdown. Document the trade-offs you chose.
                  </Typography>
                </Paper>

                {/* Communication Cadence */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: themeColors.primary }}>
                    <NotificationsActiveIcon sx={{ color: themeColors.primary }} /> Communication Cadence
                  </Typography>
                  <List dense>
                    {commsCadence.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mt: 2 }}>
                    Consistent updates reduce panic. Even if you have no new findings, send a short status update to
                    stakeholders. "No change" is better than silence, especially during high-severity incidents.
                  </Typography>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Lessons Learned: Post-Incident Review
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    The lessons learned phase is where response turns into improvement. It is not about blame; it is about
                    identifying gaps and preventing recurrence. For beginners, the easiest way to run this is with a simple
                    timeline review: What happened? When did we detect it? What slowed us down? What should we automate?
                  </Typography>
                  <List dense>
                    {[
                      "Review the incident timeline end-to-end with all stakeholders.",
                      "Identify detection gaps and add new rules or data sources.",
                      "Assess response delays (approvals, tooling, unclear ownership).",
                      "Document what worked well and repeat it in future playbooks.",
                      "Create concrete action items with owners and due dates.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "success.main" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                    A good lessons learned review ends with changes: updated playbooks, tuned detections, or improved training.
                    If no changes occur, the review was incomplete.
                  </Typography>
                </Paper>
              </Paper>
            </Box>

            {/* Incident Types Section */}
            <Box id="incident-types" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <WarningAmberIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      ⚠️ Incident Types & Response Procedures
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>Understanding Attack Vectors</AlertTitle>
                  Each incident type requires specific detection strategies, containment procedures, and forensic approaches.
                  Use the technical indicators and investigation queries for immediate triage.
                </Alert>

                {incidentTypes.map((incident, idx) => (
                  <Accordion key={idx} defaultExpanded={idx === 0} sx={{ mb: 1, bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                        <Box
                          sx={{
                            width: 48,
                            height: 48,
                            borderRadius: 2,
                            bgcolor: alpha(
                              incident.severity === "Critical" ? "#dc2626" : 
                              incident.severity === "High" ? "#f59e0b" : 
                              incident.severity === "Medium" ? "#3b82f6" : "#10b981",
                              0.1
                            ),
                            color: incident.severity === "Critical" ? "#dc2626" : 
                                   incident.severity === "High" ? "#f59e0b" : 
                                   incident.severity === "Medium" ? "#3b82f6" : "#10b981",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                          }}
                        >
                          {incident.icon}
                        </Box>
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="h6" sx={{ fontWeight: 700 }}>
                            {incident.type}
                          </Typography>
                        </Box>
                        <Chip 
                          label={`Severity: ${incident.severity}`} 
                          size="small" 
                          sx={{ 
                            bgcolor: alpha(
                              incident.severity === "Critical" ? "#dc2626" : 
                              incident.severity === "High" ? "#f59e0b" : 
                              incident.severity === "Medium" ? "#3b82f6" : "#10b981",
                              0.1
                            ), 
                            color: incident.severity === "Critical" ? "#dc2626" : 
                                   incident.severity === "High" ? "#f59e0b" : 
                                   incident.severity === "Medium" ? "#3b82f6" : "#10b981"
                          }} 
                        />
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={3}>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Indicators of Compromise
                          </Typography>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                            {incident.indicators.map((ind, i) => (
                              <Chip key={i} label={ind} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                            ))}
                          </Box>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Initial Response Steps
                          </Typography>
                          <Stepper orientation="vertical" sx={{ "& .MuiStepLabel-root": { py: 0 } }}>
                            {incident.initialSteps.map((step, i) => (
                              <Step key={i} active>
                                <StepLabel>
                                  <Typography variant="body2">{step}</Typography>
                                </StepLabel>
                              </Step>
                            ))}
                          </Stepper>
                        </Grid>

                        {/* Technical Indicators */}
                        <Grid item xs={12}>
                          <Divider sx={{ my: 1 }} />
                          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                            Technical Indicators
                          </Typography>
                          <List dense>
                            {incident.technicalIndicators?.map((ti, i) => (
                              <ListItem key={i} sx={{ py: 0.25 }}>
                                <ListItemIcon sx={{ minWidth: 24 }}>
                                  <WarningAmberIcon sx={{ fontSize: 14, color: "warning.main" }} />
                                </ListItemIcon>
                                <ListItemText primary={ti} primaryTypographyProps={{ variant: "body2" }} />
                              </ListItem>
                            ))}
                          </List>
                        </Grid>

                        {/* Investigation Queries */}
                        {incident.investigationQueries && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                              Investigation Queries
                            </Typography>
                            <Paper
                              sx={{
                                p: 2,
                                bgcolor: "#1a1a2e",
                                borderRadius: 1,
                                fontFamily: "monospace",
                                fontSize: "0.75rem",
                                overflow: "auto",
                                maxHeight: 200,
                              }}
                            >
                              <pre style={{ margin: 0, color: "#22d3ee", whiteSpace: "pre-wrap" }}>
                                {incident.investigationQueries}
                              </pre>
                            </Paper>
                          </Grid>
                        )}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                ))}

                {/* Attack Chain Reference */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mt: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    MITRE ATT&CK - Common Attack Chain
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Most attacks follow a predictable kill chain. Understanding this helps prioritize detection at each stage.
                  </Typography>
                  <Stepper alternativeLabel sx={{ mb: 2 }}>
                    {["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "Actions"].map((stage) => (
                      <Step key={stage} completed>
                        <StepLabel>{stage}</StepLabel>
                      </Step>
                    ))}
                  </Stepper>
                  <Alert severity="warning">
                    <AlertTitle>Detection Priority</AlertTitle>
                    Focus detection efforts on Delivery, Exploitation, and C2 stages - these offer the best 
                    balance of detection fidelity and remediation opportunity before significant damage occurs.
                  </Alert>
                </Paper>
              </Paper>
            </Box>

            {/* Playbooks Section */}
            <Box id="playbooks" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <AssignmentIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      📖 Incident Response Playbooks
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>Incident Response Playbooks</AlertTitle>
                  Playbooks provide step-by-step procedures for handling specific incident types. Customize these for your organization.
                </Alert>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Playbooks are not just checklists. They are decision guides that help teams respond consistently under
                  pressure. A good playbook tells you what to do, why it matters, and when to escalate. For beginners,
                  the most useful playbooks include clear stop points: "pause here and notify legal" or "pause here and
                  confirm containment before proceeding."
                </Typography>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Ransomware Response Playbook
                  </Typography>
                  <Divider sx={{ mb: 2, borderColor: themeColors.border }} />
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Ransomware response is time-sensitive because encryption can spread. Your priorities are to stop
                    the spread, preserve evidence, and protect backups. Do not reimage or wipe systems until evidence
                    is captured and leadership approves the recovery plan.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Beginner tip: treat every infected system as a potential foothold. Even after encryption stops, the
                    attacker may still be present. That is why evidence collection and persistence checks are critical.
                  </Typography>
                  
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#dc2626" }}>
                    Immediate Actions (First 15 minutes)
                  </Typography>
                  <CodeBlock>{`1. ISOLATE affected systems - disconnect from network (DO NOT power off)
2. ALERT IR team lead and escalate to management
3. PRESERVE memory dump before any other actions
4. IDENTIFY ransomware variant (check ransom note, file extensions)
5. DOCUMENT everything - screenshots, timestamps, affected systems`}</CodeBlock>

                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 3, mb: 1, color: "#f59e0b" }}>
                    Investigation Phase (1-4 hours)
                  </Typography>
                  <CodeBlock>{`1. Determine initial infection vector (phishing, RDP, vulnerability)
2. Identify patient zero and timeline
3. Map lateral movement and affected systems
4. Check for data exfiltration (double extortion)
5. Assess backup integrity and availability
6. Collect IOCs (hashes, IPs, domains)`}</CodeBlock>

                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 3, mb: 1, color: "#10b981" }}>
                    Recovery Considerations
                  </Typography>
                  <CodeBlock>{`1. DO NOT pay ransom without executive/legal approval
2. Check for decryptor availability (NoMoreRansom.org)
3. Restore from clean backups (verify integrity first)
4. Rebuild systems if backups unavailable
5. Implement additional controls before reconnecting
6. Report to law enforcement (FBI IC3, local authorities)`}</CodeBlock>

                  <Paper sx={{ p: 2, mt: 3, borderRadius: 2, bgcolor: alpha("#0f172a", 0.5) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#e2e8f0" }}>
                      Walkthrough: First-Hour Ransomware Response
                    </Typography>
                    <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                      Minute 0-10: isolate affected hosts and capture memory. Minute 10-30: identify the ransomware variant,
                      confirm scope, and secure backups. Minute 30-60: notify leadership, begin broader containment, and
                      start initial forensics collection. This timeline keeps evidence intact while limiting damage.
                    </Typography>
                  </Paper>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Phishing/Credential Compromise Playbook
                  </Typography>
                  <Divider sx={{ mb: 2, borderColor: themeColors.border }} />
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Phishing incidents move fast because a single stolen credential can lead to email forwarding rules,
                    lateral movement, and data theft. The key is to identify who interacted with the email, revoke access,
                    and search for post-compromise activity. Treat every affected account as potentially compromised.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Beginner tip: after resetting passwords, check for persistence mechanisms like OAuth app grants,
                    mailbox rules, or MFA device changes. Attackers often leave these behind to regain access later.
                  </Typography>
                  
                  <CodeBlock>{`IMMEDIATE ACTIONS:
1. Block sender domain/email address
2. Quarantine similar emails in all mailboxes
3. Identify all recipients who clicked/opened
4. Reset passwords for compromised accounts
5. Revoke active sessions and tokens

INVESTIGATION:
1. Check for mailbox rules/forwarding
2. Review login history for anomalies
3. Search for lateral movement
4. Check for data access/exfiltration
5. Review MFA status and logs

REMEDIATION:
1. Enable/enforce MFA if not already
2. Update email filtering rules
3. Conduct user awareness training
4. Report to anti-phishing working group`}</CodeBlock>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Data Breach Response Playbook
                  </Typography>
                  <Divider sx={{ mb: 2, borderColor: themeColors.border }} />
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Data breaches are primarily legal and reputational events, not just technical ones. Your first goal
                    is to stop the leak. Your second goal is to accurately measure impact. Any public statement must be
                    coordinated with legal and communications teams to avoid regulatory penalties.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    Beginner tip: document exactly what data was accessed or exfiltrated. Regulators and customers will
                    ask for specifics, and vague answers can increase penalties or loss of trust.
                  </Typography>
                  
                  <CodeBlock>{`IMMEDIATE ACTIONS:
1. Contain the breach - stop ongoing data loss
2. Preserve all evidence and logs
3. Notify legal, compliance, and executive team
4. Begin impact assessment

INVESTIGATION:
1. Identify what data was accessed/exfiltrated
2. Determine affected individuals/records count
3. Establish timeline of unauthorized access
4. Identify attack vector and threat actor
5. Check for regulatory notification requirements

NOTIFICATION (as required by law/regulation):
1. Prepare notification content with legal
2. Notify affected individuals
3. Notify regulators (GDPR: 72 hours)
4. Prepare public statement if necessary
5. Set up support resources (credit monitoring, hotline)`}</CodeBlock>
                </Paper>
              </Paper>
            </Box>

            {/* Detection Section */}
            <Box id="detection" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <SearchIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      🔍 Detection & Monitoring
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>Detection & Monitoring</AlertTitle>
                  Effective detection requires monitoring multiple data sources, correlating events, and understanding common attack patterns.
                </Alert>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Beginners should think of detection as a layered safety net. One log source is not enough. A suspicious
                  process in endpoint data becomes stronger evidence when the same host also shows anomalous network
                  connections or unusual authentication activity. The goal is not to find a single "smoking gun," but to
                  build a consistent picture across multiple sources.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Start with high-confidence signals: admin account changes, new services, unusual login locations, or
                  execution of tools like PowerShell and PsExec. Then move toward behavioral indicators like beaconing,
                  data staging, or privilege escalation. This progression helps reduce false positives.
                </Typography>

                {/* Critical Windows Event IDs */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Critical Windows Event IDs
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    These Windows Event IDs are essential for detecting common attack techniques. Configure your SIEM to alert on these events.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Event ID</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Importance</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {windowsEventIds.map((evt) => (
                          <TableRow key={evt.id}>
                            <TableCell>
                              <Chip label={evt.id} size="small" sx={{ fontWeight: 700, fontFamily: "monospace" }} />
                            </TableCell>
                            <TableCell>{evt.description}</TableCell>
                            <TableCell>
                              <Chip label={evt.category} size="small" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{evt.importance}</Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>

                {/* Key Data Sources */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Key Data Sources
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    These sources give you visibility across the environment. If you are missing one, document the gap and
                    prioritize it in your IR readiness plan. Data completeness matters as much as data volume.
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { name: "Windows Event Logs", examples: "Security, System, PowerShell, Sysmon", icon: <ComputerIcon /> },
                      { name: "Network Traffic", examples: "Firewall logs, IDS/IPS, NetFlow, DNS", icon: <NetworkCheckIcon /> },
                      { name: "Endpoint Detection", examples: "EDR alerts, AV logs, process monitoring", icon: <SecurityIcon /> },
                      { name: "Authentication", examples: "AD logs, SSO, VPN, MFA", icon: <LockIcon /> },
                      { name: "Email Security", examples: "Email gateway, phishing reports, DLP", icon: <EmailIcon /> },
                      { name: "Cloud Services", examples: "Azure AD, AWS CloudTrail, GCP audit", icon: <CloudIcon /> },
                    ].map((src) => (
                      <Grid item xs={12} sm={6} md={4} key={src.name}>
                        <Card sx={{ p: 2, bgcolor: alpha(themeColors.primary, 0.05), border: `1px solid ${themeColors.border}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            {src.icon}
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{src.name}</Typography>
                          </Box>
                          <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{src.examples}</Typography>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                {/* Sigma Detection Rules */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Sigma Detection Rules
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Sigma is a generic signature format for SIEM systems. These rules can be converted to your specific platform (Splunk, Elastic, etc.)
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    For beginners, Sigma rules are a great way to learn detection patterns without being locked to a single
                    SIEM. Treat them as templates and adjust field names to match your data. Always test a rule against
                    known benign activity to understand expected false positives.
                  </Typography>
                  {sigmaRules.map((rule, idx) => (
                    <Accordion key={idx} sx={{ mb: 1, bgcolor: themeColors.bgCard, "&:before": { display: "none" } }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <DataObjectIcon sx={{ color: themeColors.primary }} />
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{rule.name}</Typography>
                            <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{rule.description}</Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Paper sx={{ p: 2, bgcolor: "#1a1a2e", borderRadius: 1, fontFamily: "monospace", fontSize: "0.75rem", overflow: "auto" }}>
                          <pre style={{ margin: 0, color: "#22d3ee", whiteSpace: "pre-wrap" }}>{rule.rule}</pre>
                        </Paper>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Paper>

                {/* MITRE ATT&CK Detection Mapping */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    MITRE ATT&CK Detection Mapping
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Map detections to ATT&CK techniques for coverage analysis
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>ID</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Data Source</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Detection Method</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          { tech: "Initial Access - Phishing", id: "T1566", source: "Email Gateway", method: "Attachment/link analysis" },
                          { tech: "Execution - PowerShell", id: "T1059.001", source: "Process Logs", method: "Script block logging" },
                          { tech: "Persistence - Scheduled Task", id: "T1053", source: "Windows Events", method: "Task creation monitoring" },
                          { tech: "Credential Access - LSASS", id: "T1003.001", source: "Sysmon", method: "Process access monitoring" },
                          { tech: "Lateral Movement - RDP", id: "T1021.001", source: "Auth Logs", method: "Remote login correlation" },
                          { tech: "Discovery - Network Scanning", id: "T1046", source: "Network Logs", method: "Port scan detection" },
                          { tech: "Collection - Data Staging", id: "T1074", source: "File Monitoring", method: "Unusual file aggregation" },
                          { tech: "Exfiltration - C2 Channel", id: "T1041", source: "Network Traffic", method: "Anomaly detection" },
                        ].map((row) => (
                          <TableRow key={row.id}>
                            <TableCell>{row.tech}</TableCell>
                            <TableCell><Chip label={row.id} size="small" /></TableCell>
                            <TableCell>{row.source}</TableCell>
                            <TableCell>{row.method}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              </Paper>
            </Box>

            {/* Tools Section */}
            <Box id="tools" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <BuildIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      🛠️ Incident Response Tools
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>Incident Response Tools</AlertTitle>
                  Essential tools for detection, collection, analysis, and case management. Build your IR toolkit based on your environment needs.
                </Alert>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Tools are only useful if you know what question they answer. For beginners, focus on a small, reliable
                  toolkit: one memory tool, one disk tool, one network tool, and one case management system. Master those
                  first before expanding. Consistency improves the quality of your evidence and your reporting.
                </Typography>

                {/* Tools by Category */}
                {["Memory Forensics", "Disk Forensics", "Network Analysis", "Log Analysis", "Malware Analysis", "Case Management"].map((category) => {
                  const categoryTools = irTools.filter(t => t.category === category);
                  if (categoryTools.length === 0) return null;
                  return (
                    <Paper key={category} sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                      <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                        {category}
                      </Typography>
                      <Grid container spacing={2}>
                        {categoryTools.map((tool) => (
                          <Grid item xs={12} md={6} key={tool.name}>
                            <Card sx={{ p: 2, height: "100%", bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}>
                              <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 1 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{tool.name}</Typography>
                                <Chip label={tool.platform || "Cross-platform"} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                              </Box>
                              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                                {tool.description}
                              </Typography>
                              {tool.usage && (
                                <Paper sx={{ p: 1, bgcolor: "#1a1a2e", borderRadius: 1, mb: 1 }}>
                                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#22d3ee", fontSize: "0.7rem" }}>
                                    {tool.usage}
                                  </Typography>
                                </Paper>
                        )}
                        <Typography
                          component="a"
                          href={tool.url}
                          target="_blank"
                          rel="noopener"
                          sx={{ color: themeColors.primary, fontSize: "0.85rem", textDecoration: "none", "&:hover": { textDecoration: "underline" } }}
                        >
                          Documentation →
                        </Typography>
                      </Card>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            );
          })}

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Quick Collection Commands
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                    These commands are designed for rapid triage. Use them when you need a fast snapshot of system state
                    before containment changes the environment. Always record timestamps and store outputs in a case folder.
                  </Typography>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 2, mb: 1 }}>
                    Windows Evidence Collection
                  </Typography>
                  <CodeBlock>{`# Volatile data collection (run first!)
systeminfo > systeminfo.txt
tasklist /v > processes.txt
netstat -anob > netstat.txt
ipconfig /all > ipconfig.txt
arp -a > arp.txt
net user > users.txt
net localgroup administrators > admins.txt
wmic process list full > wmic_processes.txt

# Event log export
wevtutil epl Security security.evtx
wevtutil epl System system.evtx
wevtutil epl Application application.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" powershell.evtx

# Memory dump (requires admin)
winpmem_mini_x64.exe memory.raw`}</CodeBlock>

                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 3, mb: 1 }}>
                    Linux Evidence Collection
                  </Typography>
                  <CodeBlock>{`# Volatile data
date > timestamp.txt
uname -a > system_info.txt
ps auxf > processes.txt
netstat -tulpn > netstat.txt
ss -tulpn > ss.txt
w > logged_users.txt
last > login_history.txt
cat /etc/passwd > passwd.txt

# Important logs
cp /var/log/auth.log ./
cp /var/log/syslog ./
cp /var/log/secure ./
journalctl --since "24 hours ago" > journal.txt

# Memory dump
sudo ./linpmem -o memory.lime`}</CodeBlock>

                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mt: 3, mb: 1 }}>
                    Network Evidence Collection
                  </Typography>
                  <CodeBlock>{`# Packet capture with tcpdump
tcpdump -i eth0 -w capture.pcap -c 10000

# Capture specific traffic
tcpdump -i any host 192.168.1.100 -w suspicious_host.pcap
tcpdump -i any port 443 -w https_traffic.pcap

# DNS query logging
tcpdump -i any port 53 -w dns_queries.pcap

# Zeek (formerly Bro) for traffic analysis
zeek -r capture.pcap local
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log`}</CodeBlock>
                </Paper>
              </Paper>
            </Box>

            {/* Documentation Section */}
            <Box id="documentation" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <ArticleIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      📄 Documentation & Templates
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Alert severity="warning" sx={{ borderRadius: 2, mb: 3 }}>
                  <AlertTitle>Documentation is Critical</AlertTitle>
                  Proper documentation supports legal proceedings, compliance requirements, and lessons learned. All timestamps should be in UTC.
                </Alert>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 3 }}>
                  Documentation is your evidence trail. If you cannot show who did what, when, and why, your response
                  will not be defensible. For beginners, the simplest habit is to write down every action and include
                  the exact time in UTC. Even a short note like "Isolated host WS-12 at 14:23 UTC" can be critical later.
                </Typography>

                {/* Documentation Templates */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Essential Documentation Templates
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    Templates standardize how your team records incidents. This reduces confusion and speeds up review.
                    Beginners should start by using the same template for every case, even small ones. Consistency makes
                    your reporting clearer and easier to audit.
                  </Typography>
                  <Grid container spacing={2}>
                    {documentationTemplates.map((doc) => (
                      <Grid item xs={12} md={6} key={doc.name}>
                        <Card sx={{ p: 2, height: "100%", bgcolor: themeColors.bgCard, border: doc.critical ? `2px solid ${alpha("#ef4444", 0.5)}` : `1px solid ${themeColors.border}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <ArticleIcon sx={{ color: doc.critical ? "#ef4444" : themeColors.primary }} />
                            <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{doc.name}</Typography>
                            {doc.critical && <Chip label="Critical" size="small" color="error" sx={{ fontSize: "0.65rem" }} />}
                          </Box>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>{doc.purpose}</Typography>
                          <Typography variant="caption" sx={{ color: themeColors.textMuted, fontStyle: "italic" }}>
                            Fields: {doc.fields}
                          </Typography>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                {/* Communication Templates */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Communication Templates
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Pre-approved communication templates help ensure consistent, accurate, and timely notifications during incidents.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    The goal is to communicate facts, not speculation. Use calm language, avoid blame, and update stakeholders
                    regularly. For external communication, always route through legal and communications teams.
                  </Typography>
                  {communicationTemplates.map((template, idx) => (
                    <Accordion key={idx} sx={{ mb: 1, bgcolor: themeColors.bgCard, "&:before": { display: "none" } }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                          <NotificationsActiveIcon sx={{ color: themeColors.primary }} />
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{template.name}</Typography>
                            <Typography variant="caption" sx={{ color: themeColors.textMuted }}>Audience: {template.audience}</Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Paper sx={{ p: 2, bgcolor: "#1a1a2e", borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem" }}>
                          <pre style={{ margin: 0, color: "#e2e8f0", whiteSpace: "pre-wrap" }}>{template.template}</pre>
                        </Paper>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Paper>

                {/* Regulatory Requirements */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Regulatory Notification Requirements
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Different regulations have specific breach notification requirements. Consult with legal counsel for your specific obligations.
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    These rules often include strict time limits. If you miss them, penalties can be severe. During an incident,
                    identify which regulations apply and document when you notified regulators or affected individuals.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 700 }}>Regulation</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Requirement</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Scope</TableCell>
                          <TableCell sx={{ fontWeight: 700 }}>Penalty</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {regulatoryRequirements.map((reg) => (
                          <TableRow key={reg.regulation}>
                            <TableCell>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <GavelIcon sx={{ fontSize: 16, color: themeColors.textMuted }} />
                                <Typography variant="body2" sx={{ fontWeight: 600 }}>{reg.regulation}</Typography>
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">{reg.requirement}</Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" sx={{ color: themeColors.textMuted }}>{reg.scope}</Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" sx={{ color: "error.main" }}>{reg.penalty}</Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>

                {/* Incident Report Template */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Incident Report Template
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    The report is the final product of an incident response. It must be readable by non-technical leaders
                    and defensible for auditors. Avoid assumptions. Use evidence and cite where each finding came from.
                  </Typography>
                  <CodeBlock>{`INCIDENT REPORT
===============

EXECUTIVE SUMMARY
-----------------
Incident ID: INC-2024-XXX
Date Detected: YYYY-MM-DD HH:MM UTC
Date Reported: YYYY-MM-DD HH:MM UTC
Classification: [Malware/Phishing/Data Breach/etc.]
Severity: [Critical/High/Medium/Low]
Status: [Open/Contained/Eradicated/Closed]

INCIDENT SUMMARY
----------------
Brief description of what happened, impact, and current status.

TIMELINE
--------
| Date/Time (UTC) | Event | Source | Actor |
|-----------------|-------|--------|-------|
| ... | ... | ... | ... |

AFFECTED SYSTEMS
----------------
- Hostname: 
- IP Address:
- Business Function:
- Data Classification:

ROOT CAUSE
----------
How did this happen? What vulnerability/weakness was exploited?

IMPACT ASSESSMENT
-----------------
- Systems Affected: X
- Users Affected: X
- Data Exposed: [Yes/No/Unknown]
- Business Impact: [Description]
- Regulatory Impact: [GDPR/HIPAA/etc.]

RESPONSE ACTIONS
----------------
1. [Action taken] - [Timestamp]
2. [Action taken] - [Timestamp]

RECOMMENDATIONS
---------------
1. [Short-term fix]
2. [Long-term improvement]

LESSONS LEARNED
---------------
- What worked well?
- What could be improved?
- Training needs identified?`}</CodeBlock>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Example: Completed Incident Report (Beginner-Friendly)
                  </Typography>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2, lineHeight: 1.7 }}>
                    This example shows how a finished report looks with clear facts, simple language, and evidence-backed
                    findings. Notice how each claim is tied to a log source or artifact.
                  </Typography>
                  <CodeBlock>{`INCIDENT REPORT (EXAMPLE)
=========================

EXECUTIVE SUMMARY
-----------------
Incident ID: INC-2024-042
Date Detected: 2024-03-18 09:12 UTC
Date Reported: 2024-03-18 09:30 UTC
Classification: Credential Compromise
Severity: High
Status: Contained

SUMMARY
-------
We detected a suspicious login to a finance mailbox from an unfamiliar IP
address. The attacker created a mailbox forwarding rule and attempted to
download sensitive attachments. The account was reset and access revoked.

TIMELINE
--------
2024-03-18 09:12 UTC  Alert: New country login (M365 sign-in logs)
2024-03-18 09:16 UTC  Forwarding rule created (Exchange audit logs)
2024-03-18 09:20 UTC  Token revoked, password reset (Azure AD logs)
2024-03-18 09:35 UTC  No further suspicious activity observed

AFFECTED SYSTEMS
----------------
- Account: j.smith@company.com
- Mailbox: Finance Team Shared Mailbox
- Source IP: 185.11.22.33 (Geo: RU)

ROOT CAUSE
----------
Credential theft via phishing email on 2024-03-17. User reported clicking a
link and entering credentials on a fake login page.

IMPACT ASSESSMENT
-----------------
- Data Exposed: 12 emails accessed, no confirmed download of attachments
- Business Impact: Low to Moderate (finance mailbox exposure)
- Regulatory Impact: None (no sensitive regulated data confirmed)

RESPONSE ACTIONS
----------------
1. Disabled account and revoked active sessions (09:20 UTC)
2. Removed mailbox forwarding rule (09:22 UTC)
3. Forced password reset and MFA re-registration (09:25 UTC)
4. Searched for similar logins across tenant (09:40 UTC)

RECOMMENDATIONS
---------------
1. Enforce phishing-resistant MFA for finance users
2. Enable alerting on mailbox forwarding rule creation
3. Provide targeted phishing training to finance department
`}</CodeBlock>
                </Paper>

                {/* Chain of Custody Log */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Chain of Custody Log
                  </Typography>
                  <CodeBlock>{`CHAIN OF CUSTODY LOG
====================

Evidence ID: EVD-2024-XXX
Case Number: INC-2024-XXX
Description: [Memory dump from workstation WS001]

EVIDENCE DETAILS
----------------
Type: [Digital/Physical]
Source System: [Hostname/IP]
Collection Method: [Tool used]
Hash (SHA256): [hash value]
Storage Location: [Secure storage path]

CUSTODY RECORD
--------------
| Date/Time (UTC) | Released By | Received By | Purpose | Location |
|-----------------|-------------|-------------|---------|----------|
| YYYY-MM-DD HH:MM | Collector | Analyst | Analysis | Lab |
| ... | ... | ... | ... | ... |

INTEGRITY VERIFICATION
----------------------
Date: YYYY-MM-DD
Verified By: [Name]
Hash Match: [Yes/No]
Notes: [Any observations]`}</CodeBlock>
                </Paper>
              </Paper>
            </Box>

            {/* Resources Section */}
            <Box id="resources" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <MenuBookIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      📚 Resources & Further Learning
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Standards & Frameworks
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { name: "NIST SP 800-61", desc: "Computer Security Incident Handling Guide", url: "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final" },
                      { name: "SANS Incident Handler's Handbook", desc: "Practical IR methodology", url: "https://www.sans.org/white-papers/33901/" },
                      { name: "CISA Incident Response Playbooks", desc: "Federal IR guidance", url: "https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf" },
                      { name: "FIRST CSIRT Services Framework", desc: "CSIRT capability building", url: "https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1" },
                    ].map((res) => (
                      <Grid item xs={12} sm={6} key={res.name}>
                        <Card sx={{ p: 2, height: "100%", bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{res.name}</Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>{res.desc}</Typography>
                          <Typography
                            component="a"
                            href={res.url}
                            target="_blank"
                            rel="noopener"
                            sx={{ color: themeColors.primary, fontSize: "0.85rem" }}
                          >
                            View Resource →
                          </Typography>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Training & Certifications
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { name: "SANS FOR508", desc: "Advanced Incident Response, Threat Hunting", provider: "SANS", level: "Advanced" },
                      { name: "SANS FOR500", desc: "Windows Forensic Analysis", provider: "SANS", level: "Intermediate" },
                      { name: "GCIH", desc: "GIAC Certified Incident Handler", provider: "GIAC", level: "Intermediate" },
                      { name: "GCFA", desc: "GIAC Certified Forensic Analyst", provider: "GIAC", level: "Advanced" },
                      { name: "eCIR", desc: "Certified Incident Responder", provider: "INE", level: "Intermediate" },
                      { name: "BTL1", desc: "Blue Team Level 1", provider: "Security Blue Team", level: "Entry" },
                    ].map((cert) => (
                      <Grid item xs={12} sm={6} md={4} key={cert.name}>
                        <Card sx={{ p: 2, height: "100%", bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "start", mb: 1 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{cert.name}</Typography>
                            <Chip label={cert.level} size="small" sx={{ fontSize: "0.65rem" }} />
                          </Box>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{cert.desc}</Typography>
                          <Typography variant="caption" sx={{ color: themeColors.primary }}>{cert.provider}</Typography>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}`, mb: 3 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Practice Labs & Ranges
                  </Typography>
                  <Grid container spacing={2}>
                    {[
                      { name: "CyberDefenders", desc: "Blue team CTF challenges with real DFIR scenarios", url: "https://cyberdefenders.org" },
                      { name: "Blue Team Labs Online", desc: "Hands-on defensive security labs", url: "https://blueteamlabs.online" },
                      { name: "LetsDefend", desc: "SOC analyst training platform", url: "https://letsdefend.io" },
                      { name: "SANS Holiday Hack", desc: "Annual DFIR challenge", url: "https://holidayhackchallenge.com" },
                    ].map((lab) => (
                      <Grid item xs={12} sm={6} key={lab.name}>
                        <Card sx={{ p: 2, bgcolor: themeColors.bgCard, border: `1px solid ${themeColors.border}` }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{lab.name}</Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>{lab.desc}</Typography>
                          <Typography
                            component="a"
                            href={lab.url}
                            target="_blank"
                            rel="noopener"
                            sx={{ color: themeColors.primary, fontSize: "0.85rem" }}
                          >
                            Visit →
                          </Typography>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: themeColors.bgNested, border: `1px solid ${themeColors.border}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: themeColors.primary }}>
                    Community Resources
                  </Typography>
                  <List>
                    {[
                      { name: "DFIR Discord", desc: "Active community of DFIR practitioners" },
                      { name: "r/computerforensics", desc: "Reddit community for digital forensics" },
                      { name: "This Week in 4n6", desc: "Weekly DFIR newsletter" },
                      { name: "13Cubed YouTube", desc: "Excellent DFIR tutorials and walkthroughs" },
                      { name: "SANS DFIR Blog", desc: "Research and case studies from SANS" },
                    ].map((res) => (
                      <ListItem key={res.name}>
                        <ListItemIcon>
                          <InfoIcon sx={{ color: themeColors.primary }} />
                        </ListItemIcon>
                        <ListItemText primary={res.name} secondary={res.desc} secondaryTypographyProps={{ sx: { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Paper>
            </Box>

            {/* Quiz Section */}
            <Box id="quiz-section" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${themeColors.border}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <QuizIcon sx={{ color: themeColors.primary }} />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 700,
                        background: `linear-gradient(135deg, ${themeColors.primary}, ${themeColors.primaryLight})`,
                        backgroundClip: "text",
                        WebkitBackgroundClip: "text",
                        WebkitTextFillColor: "transparent",
                      }}
                    >
                      📝 Knowledge Check
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>

                <QuizSection
                  questions={quizQuestions}
                  accentColor={themeColors.primary}
                  title="Incident Response Knowledge Check"
                  description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
                  questionsPerQuiz={QUIZ_QUESTION_COUNT}
                />
              </Paper>
            </Box>
          </Grid>
        </Grid>

        {/* Mobile Navigation Drawer */}
        <Drawer
          anchor="left"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          sx={{ display: { xs: "block", md: "none" } }}
        >
          <Box sx={{ width: 280, pt: 2, pb: 4, bgcolor: themeColors.bgCard, height: "100%" }}>
            <Typography variant="h6" sx={{ px: 2, mb: 2, fontWeight: 700, color: themeColors.primary }}>
              Navigation
            </Typography>
            {sidebarNav}
          </Box>
        </Drawer>

        {/* Mobile FABs */}
        <Fab
          size="small"
          sx={{
            position: "fixed",
            bottom: 80,
            right: 16,
            display: { xs: "flex", md: "none" },
            bgcolor: themeColors.primary,
            "&:hover": { bgcolor: themeColors.primaryLight },
          }}
          onClick={() => setMobileNavOpen(true)}
        >
          <ListAltIcon />
        </Fab>
        <Fab
          size="small"
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            display: { xs: "flex", md: "none" },
            bgcolor: themeColors.primary,
            "&:hover": { bgcolor: themeColors.primaryLight },
          }}
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Container>
    </LearnPageLayout>
  );
}
