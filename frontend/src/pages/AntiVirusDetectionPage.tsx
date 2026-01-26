import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
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
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import SearchIcon from "@mui/icons-material/Search";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import QuizIcon from "@mui/icons-material/Quiz";
import MenuIcon from "@mui/icons-material/Menu";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import InfoIcon from "@mui/icons-material/Info";
import DashboardIcon from "@mui/icons-material/Dashboard";
import TerminalIcon from "@mui/icons-material/Terminal";
import AssignmentIcon from "@mui/icons-material/Assignment";
import { Link } from "react-router-dom";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

const themeColors = {
  primary: "#22c55e",
  primaryLight: "#4ade80",
  secondary: "#14b8a6",
  accent: "#3b82f6",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(34, 197, 94, 0.2)",
  textMuted: "#94a3b8",
};

const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <DashboardIcon fontSize="small" /> },
  { id: "how-av-works", label: "How AV Works", icon: <SearchIcon fontSize="small" /> },
  { id: "detection-methods", label: "Detection Methods", icon: <BugReportIcon fontSize="small" /> },
  { id: "alert-anatomy", label: "Alert Anatomy", icon: <InfoIcon fontSize="small" /> },
  { id: "signals-artifacts", label: "Signals & Artifacts", icon: <ShieldIcon fontSize="small" /> },
  { id: "tuning-metrics", label: "Tuning & Metrics", icon: <SecurityIcon fontSize="small" /> },
  { id: "platform-checks", label: "Platform Checks", icon: <TerminalIcon fontSize="small" /> },
  { id: "practice-lab", label: "Practice Lab", icon: <TerminalIcon fontSize="small" /> },
  { id: "triage-response", label: "Triage & Response", icon: <AssignmentIcon fontSize="small" /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon fontSize="small" /> },
];

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
        bgcolor: themeColors.bgNested,
        borderRadius: 2,
        position: "relative",
        my: 2,
        border: `1px solid ${themeColors.border}`,
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: themeColors.primary, color: "#0b1020" }} />
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

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#22c55e";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Antivirus detection primarily aims to:",
    options: [
      "Block all network traffic",
      "Identify and stop malicious or risky activity",
      "Disable user accounts",
      "Encrypt files automatically",
    ],
    correctAnswer: 1,
    explanation: "AV tools detect and stop malicious or suspicious behavior.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "A signature-based detection relies on:",
    options: [
      "Known patterns or hashes",
      "User surveys",
      "Backup schedules",
      "System uptime",
    ],
    correctAnswer: 0,
    explanation: "Signatures match known malware patterns or hashes.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Heuristic detection focuses on:",
    options: [
      "Exact hash matches",
      "Suspicious traits or structures",
      "Only network traffic",
      "Only user input",
    ],
    correctAnswer: 1,
    explanation: "Heuristics look for patterns and traits that suggest malware.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "Behavior monitoring detects:",
    options: [
      "Runtime actions like injection or persistence",
      "Only file names",
      "Only email subjects",
      "Only timestamps",
    ],
    correctAnswer: 0,
    explanation: "Behavior monitoring watches for suspicious runtime activity.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Reputation-based detection uses:",
    options: [
      "File prevalence and cloud verdicts",
      "Only local hashes",
      "Only user permissions",
      "Only DNS caches",
    ],
    correctAnswer: 0,
    explanation: "Reputation checks use cloud intelligence and prevalence data.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "A false positive is:",
    options: [
      "Malware that is missed",
      "A safe file flagged as malicious",
      "A confirmed threat",
      "A blocked IP",
    ],
    correctAnswer: 1,
    explanation: "False positives are benign files or actions flagged incorrectly.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "A false negative is:",
    options: [
      "A safe file flagged",
      "Malware that is not detected",
      "A backup failure",
      "A policy violation",
    ],
    correctAnswer: 1,
    explanation: "False negatives are threats that evade detection.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "Quarantine means:",
    options: [
      "Deleting logs",
      "Isolating a file so it cannot run",
      "Encrypting the file",
      "Publishing a report",
    ],
    correctAnswer: 1,
    explanation: "Quarantine prevents execution while preserving evidence.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "An AV alert should include:",
    options: [
      "File path, hash, and process details",
      "Only the user name",
      "Only the hostname",
      "Only the timestamp",
    ],
    correctAnswer: 0,
    explanation: "Context helps validate and investigate alerts.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Which is a common detection signal?",
    options: [
      "Office app spawning a script engine",
      "Normal system updates",
      "Printer status change",
      "Wallpaper change",
    ],
    correctAnswer: 0,
    explanation: "Unusual parent-child process chains are suspicious.",
  },
  {
    id: 11,
    topic: "Detection Methods",
    question: "Signature-based detection is strong because it is:",
    options: [
      "Fast and accurate for known threats",
      "Best for unknown malware",
      "Always low noise",
      "Only cloud-based",
    ],
    correctAnswer: 0,
    explanation: "Signatures are effective for known threats.",
  },
  {
    id: 12,
    topic: "Detection Methods",
    question: "A weakness of signatures is:",
    options: [
      "They miss new or modified malware",
      "They require no updates",
      "They are too slow",
      "They are always wrong",
    ],
    correctAnswer: 0,
    explanation: "New variants can evade fixed signatures.",
  },
  {
    id: 13,
    topic: "Detection Methods",
    question: "Heuristic detection can cause:",
    options: [
      "False positives",
      "Guaranteed accuracy",
      "No alerts",
      "Only hash matches",
    ],
    correctAnswer: 0,
    explanation: "Heuristics trade accuracy for broader coverage.",
  },
  {
    id: 14,
    topic: "Detection Methods",
    question: "Behavior-based detection is useful for:",
    options: [
      "Fileless malware",
      "Only signed apps",
      "Only text files",
      "Only backups",
    ],
    correctAnswer: 0,
    explanation: "Behavior monitoring catches threats without static files.",
  },
  {
    id: 15,
    topic: "Detection Methods",
    question: "Cloud reputation checks can be limited when:",
    options: [
      "Systems are offline or isolated",
      "The file is known",
      "The file is signed",
      "The hash is common",
    ],
    correctAnswer: 0,
    explanation: "Cloud checks rely on connectivity and external data.",
  },
  {
    id: 16,
    topic: "Detection Methods",
    question: "A PUA alert usually means:",
    options: [
      "Potentially unwanted application detected",
      "Confirmed ransomware",
      "A kernel exploit",
      "A clean file",
    ],
    correctAnswer: 0,
    explanation: "PUA flags software that is unwanted but not always malicious.",
  },
  {
    id: 17,
    topic: "Detection Methods",
    question: "Why keep signatures updated?",
    options: [
      "To detect newly identified threats",
      "To reduce CPU usage only",
      "To disable alerts",
      "To remove logs",
    ],
    correctAnswer: 0,
    explanation: "New signatures improve coverage for recent threats.",
  },
  {
    id: 18,
    topic: "Detection Methods",
    question: "Machine learning detections typically use:",
    options: [
      "Features derived from file or behavior",
      "Only file names",
      "Only user roles",
      "Only DNS logs",
    ],
    correctAnswer: 0,
    explanation: "ML models score features from files or behavior.",
  },
  {
    id: 19,
    topic: "Detection Methods",
    question: "Why are allowlists used?",
    options: [
      "To reduce false positives for trusted software",
      "To disable antivirus entirely",
      "To increase malware exposure",
      "To avoid patching",
    ],
    correctAnswer: 0,
    explanation: "Allowlists prevent known good tools from triggering alerts.",
  },
  {
    id: 20,
    topic: "Detection Methods",
    question: "Blocking a hash is effective because:",
    options: [
      "It stops a specific known file",
      "It stops all variants",
      "It replaces behavior monitoring",
      "It prevents phishing",
    ],
    correctAnswer: 0,
    explanation: "Hash blocking is precise but narrow in scope.",
  },
  {
    id: 21,
    topic: "Signals",
    question: "A process running from a user temp folder is:",
    options: [
      "Often suspicious and worth review",
      "Always safe",
      "Always a system file",
      "Never relevant",
    ],
    correctAnswer: 0,
    explanation: "Malware often runs from temp or user-writable locations.",
  },
  {
    id: 22,
    topic: "Signals",
    question: "Which is a suspicious parent-child process chain?",
    options: [
      "winword.exe -> powershell.exe",
      "explorer.exe -> notepad.exe",
      "svchost.exe -> lsass.exe",
      "chrome.exe -> chrome.exe",
    ],
    correctAnswer: 0,
    explanation: "Office spawning scripts is a common attack pattern.",
  },
  {
    id: 23,
    topic: "Signals",
    question: "Repeated registry changes can indicate:",
    options: [
      "Persistence attempts",
      "Normal browsing",
      "Printer activity",
      "Backup verification",
    ],
    correctAnswer: 0,
    explanation: "Persistence often uses registry Run keys.",
  },
  {
    id: 24,
    topic: "Signals",
    question: "Unexpected outbound connections may indicate:",
    options: [
      "Command and control traffic",
      "Normal printing",
      "Disk cleanup",
      "Screen lock",
    ],
    correctAnswer: 0,
    explanation: "Malware often connects to external servers.",
  },
  {
    id: 25,
    topic: "Signals",
    question: "Unsigned binaries can be:",
    options: [
      "Higher risk and require review",
      "Always safe",
      "Guaranteed system files",
      "Always blocked by OS",
    ],
    correctAnswer: 0,
    explanation: "Unsigned files require extra scrutiny.",
  },
  {
    id: 26,
    topic: "Signals",
    question: "A sudden spike in outbound traffic may indicate:",
    options: [
      "Data exfiltration",
      "Normal updates only",
      "User logout",
      "A screen lock",
    ],
    correctAnswer: 0,
    explanation: "Exfiltration often causes unusual outbound spikes.",
  },
  {
    id: 27,
    topic: "Signals",
    question: "Script execution from email attachments often indicates:",
    options: [
      "Phishing or malware delivery",
      "Routine system tasks",
      "OS updates",
      "Normal backups",
    ],
    correctAnswer: 0,
    explanation: "Email attachments are a common malware vector.",
  },
  {
    id: 28,
    topic: "Signals",
    question: "Repeated AV alerts on the same host suggest:",
    options: [
      "Incomplete cleanup or persistence",
      "A clean system",
      "Only a user error",
      "No issue",
    ],
    correctAnswer: 0,
    explanation: "Repeated detections can indicate persistence.",
  },
  {
    id: 29,
    topic: "Signals",
    question: "Command line arguments are useful because:",
    options: [
      "They show how a process was executed",
      "They hide evidence",
      "They reduce alert noise",
      "They encrypt files",
    ],
    correctAnswer: 0,
    explanation: "Command lines provide critical execution context.",
  },
  {
    id: 30,
    topic: "Signals",
    question: "An AV alert without file hash is:",
    options: [
      "Harder to validate and should be enriched",
      "Always safe",
      "Always critical",
      "Never important",
    ],
    correctAnswer: 0,
    explanation: "Hashes help correlate and validate alerts.",
  },
  {
    id: 31,
    topic: "Triage",
    question: "First step in triage is to:",
    options: [
      "Confirm alert details and scope",
      "Delete the file immediately",
      "Disable all accounts",
      "Ignore the alert",
    ],
    correctAnswer: 0,
    explanation: "Confirming details prevents mistakes and guides response.",
  },
  {
    id: 32,
    topic: "Triage",
    question: "When deciding severity, consider:",
    options: [
      "Asset criticality and impact",
      "Only file size",
      "Only vendor name",
      "Only user role",
    ],
    correctAnswer: 0,
    explanation: "Severity depends on impact and system importance.",
  },
  {
    id: 33,
    topic: "Triage",
    question: "Containment may involve:",
    options: [
      "Isolating the host from the network",
      "Disabling all logs",
      "Deleting backups",
      "Ignoring the alert",
    ],
    correctAnswer: 0,
    explanation: "Isolation limits spread during investigation.",
  },
  {
    id: 34,
    topic: "Triage",
    question: "Escalate to incident response when:",
    options: [
      "Multiple systems show similar alerts",
      "Only one benign file is flagged",
      "Only a user complaint is received",
      "No evidence exists",
    ],
    correctAnswer: 0,
    explanation: "Widespread indicators warrant IR escalation.",
  },
  {
    id: 35,
    topic: "Triage",
    question: "Why capture evidence before cleaning?",
    options: [
      "To support investigation and root cause analysis",
      "To reduce storage",
      "To hide alerts",
      "To speed up scans",
    ],
    correctAnswer: 0,
    explanation: "Evidence is critical for analysis and reporting.",
  },
  {
    id: 36,
    topic: "Triage",
    question: "When handling false positives, you should:",
    options: [
      "Validate with additional evidence and document decisions",
      "Disable AV completely",
      "Ignore all future alerts",
      "Delete logs",
    ],
    correctAnswer: 0,
    explanation: "Validation and documentation prevent repeated errors.",
  },
  {
    id: 37,
    topic: "Triage",
    question: "An allowlist entry should be:",
    options: [
      "Approved and documented with justification",
      "Added by any user",
      "Hidden from audit logs",
      "Applied globally without review",
    ],
    correctAnswer: 0,
    explanation: "Allowlisting must be controlled and documented.",
  },
  {
    id: 38,
    topic: "Triage",
    question: "A safe proof of detection is to:",
    options: [
      "Use benign test samples in a lab",
      "Deploy malware in production",
      "Disable telemetry",
      "Turn off AV",
    ],
    correctAnswer: 0,
    explanation: "Testing should be safe and controlled.",
  },
  {
    id: 39,
    topic: "Triage",
    question: "Evidence to capture should include:",
    options: [
      "Hash, path, user, and process tree",
      "Only the hostname",
      "Only the timestamp",
      "Only the vendor name",
    ],
    correctAnswer: 0,
    explanation: "Context is essential for accurate investigation.",
  },
  {
    id: 40,
    topic: "Triage",
    question: "If an alert repeats after cleanup, you should:",
    options: [
      "Investigate persistence and scope",
      "Ignore it",
      "Disable AV",
      "Assume it is a false positive",
    ],
    correctAnswer: 0,
    explanation: "Repeated alerts can indicate persistence or reinfection.",
  },
  {
    id: 41,
    topic: "Telemetry",
    question: "Process creation logs provide:",
    options: [
      "Command line and parent process context",
      "Disk sector size",
      "Network routes only",
      "User passwords",
    ],
    correctAnswer: 0,
    explanation: "Process logs show how and by whom a process was started.",
  },
  {
    id: 42,
    topic: "Telemetry",
    question: "File creation events are helpful for:",
    options: [
      "Tracing the origin of a detected file",
      "Measuring CPU speed",
      "Updating drivers",
      "Managing users",
    ],
    correctAnswer: 0,
    explanation: "File events show how files appeared on disk.",
  },
  {
    id: 43,
    topic: "Telemetry",
    question: "Network logs can reveal:",
    options: [
      "Outbound connections to suspicious domains",
      "File system timestamps",
      "Registry keys",
      "Local group membership",
    ],
    correctAnswer: 0,
    explanation: "Network logs show external communications.",
  },
  {
    id: 44,
    topic: "Telemetry",
    question: "AV engine logs typically include:",
    options: [
      "Detection name, action taken, and file details",
      "Only the OS version",
      "Only the hostname",
      "Only the user name",
    ],
    correctAnswer: 0,
    explanation: "Engine logs provide detection metadata and actions.",
  },
  {
    id: 45,
    topic: "Telemetry",
    question: "Correlation helps because it:",
    options: [
      "Links alerts to related activity across logs",
      "Deletes false positives",
      "Disables telemetry",
      "Encrypts evidence",
    ],
    correctAnswer: 0,
    explanation: "Correlation provides broader context for alerts.",
  },
  {
    id: 46,
    topic: "Telemetry",
    question: "Which is a common log source for endpoint activity?",
    options: ["EDR telemetry", "Printer logs only", "BIOS logs", "Monitor settings"],
    correctAnswer: 0,
    explanation: "EDR provides rich endpoint visibility.",
  },
  {
    id: 47,
    topic: "Telemetry",
    question: "A process tree is useful to:",
    options: [
      "Understand parent-child execution relationships",
      "Encrypt evidence",
      "Change permissions",
      "Disable alerts",
    ],
    correctAnswer: 0,
    explanation: "Process trees reveal how activity started.",
  },
  {
    id: 48,
    topic: "Telemetry",
    question: "Why capture user context?",
    options: [
      "To understand who executed the action",
      "To hide evidence",
      "To reduce noise",
      "To delete logs",
    ],
    correctAnswer: 0,
    explanation: "User context helps attribute activity.",
  },
  {
    id: 49,
    topic: "Telemetry",
    question: "Why capture timestamps precisely?",
    options: [
      "To align events across systems",
      "To reduce alert volume",
      "To disable detection",
      "To compress files",
    ],
    correctAnswer: 0,
    explanation: "Precise timing is key to accurate timelines.",
  },
  {
    id: 50,
    topic: "Telemetry",
    question: "A detection without a process name is:",
    options: [
      "Less useful and should be enriched",
      "Always critical",
      "Always safe",
      "Complete evidence",
    ],
    correctAnswer: 0,
    explanation: "Process context is important for investigation.",
  },
  {
    id: 51,
    topic: "Platform Checks",
    question: "Windows Defender status can be checked with:",
    options: ["Get-MpComputerStatus", "netstat", "ipconfig", "whoami"],
    correctAnswer: 0,
    explanation: "Get-MpComputerStatus reports Defender status.",
  },
  {
    id: 52,
    topic: "Platform Checks",
    question: "A quick scan in Defender is started with:",
    options: ["Start-MpScan -ScanType QuickScan", "Get-Process", "net user", "Get-Service"],
    correctAnswer: 0,
    explanation: "Start-MpScan triggers a Defender scan.",
  },
  {
    id: 53,
    topic: "Platform Checks",
    question: "ClamAV scanning typically uses:",
    options: ["clamscan -r /path", "ps aux", "ls -la", "grep -r"],
    correctAnswer: 0,
    explanation: "clamscan runs recursive scans on directories.",
  },
  {
    id: 54,
    topic: "Platform Checks",
    question: "ClamAV signatures are updated with:",
    options: ["freshclam", "apt update", "yum update", "brew update"],
    correctAnswer: 0,
    explanation: "freshclam updates ClamAV signature databases.",
  },
  {
    id: 55,
    topic: "Platform Checks",
    question: "macOS Gatekeeper status is checked with:",
    options: ["spctl --status", "dscl . -list", "launchctl list", "scutil --dns"],
    correctAnswer: 0,
    explanation: "spctl controls and reports Gatekeeper status.",
  },
  {
    id: 56,
    topic: "Platform Checks",
    question: "XProtect is:",
    options: ["Built-in macOS malware protection", "A Linux firewall", "A Windows registry key", "A password manager"],
    correctAnswer: 0,
    explanation: "XProtect is macOS built-in malware protection.",
  },
  {
    id: 57,
    topic: "Platform Checks",
    question: "When running scans in production, you should:",
    options: [
      "Follow change control and avoid disruption",
      "Disable alerts",
      "Ignore scope",
      "Remove telemetry",
    ],
    correctAnswer: 0,
    explanation: "Production scans should be controlled to avoid impact.",
  },
  {
    id: 58,
    topic: "Platform Checks",
    question: "A baseline check should include:",
    options: [
      "AV enabled, signatures current, exclusions reviewed",
      "Only disk space",
      "Only CPU usage",
      "Only user count",
    ],
    correctAnswer: 0,
    explanation: "Baseline checks confirm protection is active and current.",
  },
  {
    id: 59,
    topic: "Platform Checks",
    question: "Why review exclusions?",
    options: [
      "Attackers may abuse excluded paths",
      "They improve encryption",
      "They block patches",
      "They reduce logs",
    ],
    correctAnswer: 0,
    explanation: "Exclusions can create blind spots if abused.",
  },
  {
    id: 60,
    topic: "Platform Checks",
    question: "A safe lab practice is to:",
    options: [
      "Use isolated test systems for scans",
      "Scan production without notice",
      "Disable AV for testing",
      "Ignore policy",
    ],
    correctAnswer: 0,
    explanation: "Use isolated labs to avoid production impact.",
  },
  {
    id: 61,
    topic: "Response",
    question: "When should you isolate a host?",
    options: [
      "When malicious activity is confirmed or spreading",
      "For every alert automatically",
      "Only after report writing",
      "Never",
    ],
    correctAnswer: 0,
    explanation: "Isolation is appropriate when there is confirmed risk.",
  },
  {
    id: 62,
    topic: "Response",
    question: "Why keep copies of quarantined files?",
    options: [
      "For analysis and evidence",
      "To run them later",
      "To ignore policies",
      "To reduce storage",
    ],
    correctAnswer: 0,
    explanation: "Quarantined files may be needed for investigation.",
  },
  {
    id: 63,
    topic: "Response",
    question: "If a detection is confirmed malicious, you should:",
    options: [
      "Contain, investigate, and remediate",
      "Ignore it",
      "Only update signatures",
      "Only notify users",
    ],
    correctAnswer: 0,
    explanation: "Confirmed threats require containment and remediation.",
  },
  {
    id: 64,
    topic: "Response",
    question: "Tuning AV rules should balance:",
    options: [
      "Coverage and false positives",
      "CPU and memory only",
      "Storage and bandwidth only",
      "User count only",
    ],
    correctAnswer: 0,
    explanation: "Effective tuning reduces noise without reducing protection.",
  },
  {
    id: 65,
    topic: "Response",
    question: "Which is a safe escalation trigger?",
    options: [
      "Multiple hosts with the same malware family",
      "One low-risk PUA",
      "A single benign file",
      "No evidence",
    ],
    correctAnswer: 0,
    explanation: "Widespread detections indicate a broader incident.",
  },
  {
    id: 66,
    topic: "Response",
    question: "Why capture process trees?",
    options: [
      "To see the initial infection path",
      "To hide evidence",
      "To reduce logs",
      "To disable scans",
    ],
    correctAnswer: 0,
    explanation: "Process trees show how the malicious process started.",
  },
  {
    id: 67,
    topic: "Response",
    question: "Which is a common next step after detection?",
    options: [
      "Hunt for related indicators across the environment",
      "Ignore other systems",
      "Disable logging",
      "Remove monitoring",
    ],
    correctAnswer: 0,
    explanation: "Hunting helps identify additional affected hosts.",
  },
  {
    id: 68,
    topic: "Response",
    question: "Why avoid destructive actions during triage?",
    options: [
      "They can destroy evidence",
      "They reduce alert volume",
      "They improve scanning",
      "They update signatures",
    ],
    correctAnswer: 0,
    explanation: "Preserving evidence is critical for investigation.",
  },
  {
    id: 69,
    topic: "Response",
    question: "A good detection note should include:",
    options: [
      "What, where, when, who, and next steps",
      "Only a file name",
      "Only a screenshot",
      "Only a host name",
    ],
    correctAnswer: 0,
    explanation: "Clear notes support handoff and response.",
  },
  {
    id: 70,
    topic: "Response",
    question: "If a file is signed by a trusted vendor but still alerts, you should:",
    options: [
      "Validate the signature and investigate further",
      "Auto-allow it",
      "Delete all logs",
      "Ignore the alert",
    ],
    correctAnswer: 0,
    explanation: "Signed files can still be abused or compromised.",
  },
  {
    id: 71,
    topic: "Best Practices",
    question: "Why keep AV policies up to date?",
    options: [
      "To adapt to new threats and reduce gaps",
      "To disable alerts",
      "To remove telemetry",
      "To reduce user count",
    ],
    correctAnswer: 0,
    explanation: "Policies need updates as threats change.",
  },
  {
    id: 72,
    topic: "Best Practices",
    question: "Why document false positives?",
    options: [
      "To improve tuning and reduce future noise",
      "To hide incidents",
      "To disable AV",
      "To delete evidence",
    ],
    correctAnswer: 0,
    explanation: "Documentation supports tuning and accountability.",
  },
  {
    id: 73,
    topic: "Best Practices",
    question: "Defense in depth for detection includes:",
    options: [
      "Combining signatures, behavior, and telemetry",
      "Only one detection method",
      "Only firewall rules",
      "Only user training",
    ],
    correctAnswer: 0,
    explanation: "Multiple layers increase detection coverage.",
  },
  {
    id: 74,
    topic: "Best Practices",
    question: "Why monitor exclusions and allowlists?",
    options: [
      "They can be abused by attackers",
      "They improve encryption",
      "They reduce patching",
      "They hide evidence",
    ],
    correctAnswer: 0,
    explanation: "Exclusions can create blind spots if misused.",
  },
  {
    id: 75,
    topic: "Best Practices",
    question: "The safest way to validate a detection workflow is:",
    options: [
      "Testing in an isolated lab environment",
      "Testing on production without notice",
      "Disabling AV",
      "Ignoring alerts",
    ],
    correctAnswer: 0,
    explanation: "Lab testing avoids risk to production systems.",
  },
];

const AntiVirusDetectionPage: React.FC = () => {
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
    <Box
      sx={{
        position: "sticky",
        top: 90,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        pr: 1,
        "&::-webkit-scrollbar": { width: "4px" },
        "&::-webkit-scrollbar-thumb": { bgcolor: themeColors.border, borderRadius: 2 },
      }}
    >
      <Typography variant="overline" sx={{ color: themeColors.textMuted, fontWeight: 600, mb: 1, display: "block" }}>
        ON THIS PAGE
      </Typography>
      <List dense disablePadding>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            disablePadding
            sx={{
              mb: 0.5,
              borderRadius: 1,
              bgcolor: activeSection === item.id ? `${themeColors.primary}15` : "transparent",
              borderLeft: activeSection === item.id ? `3px solid ${themeColors.primary}` : "3px solid transparent",
            }}
          >
            <Box
              onClick={() => scrollToSection(item.id)}
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
                py: 0.75,
                px: 1.5,
                cursor: "pointer",
                width: "100%",
                color: activeSection === item.id ? themeColors.primary : themeColors.textMuted,
                "&:hover": { color: themeColors.primary },
                transition: "color 0.2s",
              }}
            >
              {item.icon}
              <Typography variant="body2" sx={{ fontWeight: activeSection === item.id ? 600 : 400 }}>
                {item.label}
              </Typography>
            </Box>
          </ListItem>
        ))}
      </List>
    </Box>
  );

  const pageContext = `This page covers antivirus detection fundamentals for beginners. Topics include how AV works, scan types, detection methods (signature-based, heuristic rules, behavior monitoring, reputation and cloud), alert anatomy, common alert types, detection signals and artifacts, tuning and metrics, and platform-specific checks for Windows Defender, Linux ClamAV, and macOS XProtect/Gatekeeper. The page covers telemetry sources, evidence capture, enrichment, severity rubric, response checklists, false positive handling, triage workflows, safe lab practice, and when to escalate incidents. Key concepts include signatures, heuristics, behavior analysis, quarantine, allowlists, and false positives/negatives.`;

  const beginnerObjectives = [
    "Explain what antivirus detection is in plain language.",
    "Understand when scans run (real-time, on-demand, scheduled).",
    "List the main detection methods: signatures, heuristics, behavior, reputation, and ML scoring.",
    "Identify the basic signals AV engines look for.",
    "Read an alert and know which fields matter.",
    "Run safe, read-only status checks on a lab system.",
    "Explain basic tuning tradeoffs and quality metrics.",
    "Write a short detection note with evidence and next steps.",
  ];
  const beginnerTerms = [
    { term: "Malware", desc: "Any malicious software: viruses, ransomware, trojans, and more." },
    { term: "Signature", desc: "A known pattern that matches previously identified malware." },
    { term: "Heuristic", desc: "A rule that looks for suspicious traits instead of exact matches." },
    { term: "Behavior", desc: "Actions at runtime such as injection, persistence, or credential access." },
    { term: "Reputation", desc: "A trust score based on how common a file is and who signed it." },
    { term: "PUA", desc: "Potentially unwanted application that may be risky but not strictly malicious." },
    { term: "Hash", desc: "A unique fingerprint of a file, often SHA-256." },
    { term: "Telemetry", desc: "Event data collected from endpoints for investigation." },
    { term: "IOC", desc: "Indicator of compromise such as a hash, domain, or file path." },
    { term: "On-access scan", desc: "Automatic scan when a file is opened, saved, or executed." },
    { term: "Quarantine", desc: "Isolating a file so it cannot run." },
    { term: "Exclusion/Allowlist", desc: "A rule that skips or permits trusted items to reduce noise." },
    { term: "False positive", desc: "A safe file flagged as malicious." },
    { term: "False negative", desc: "A malicious file that is not detected." },
    { term: "EDR", desc: "Endpoint Detection and Response, which adds richer monitoring and response." },
  ];
  const scanTypes = [
    { title: "Real-time/on-access scans", desc: "Scans files as they are opened, saved, or executed to prevent immediate harm." },
    { title: "On-demand scans", desc: "Manual scans started by an analyst or user for spot checks." },
    { title: "Scheduled scans", desc: "Regular scans that catch dormant files that were not executed." },
    { title: "Boot/offline scans", desc: "Runs before the OS fully starts to catch deeply embedded threats." },
  ];
  const scanWorkflow = [
    { step: "1. Intake and metadata", detail: "When a file appears, the engine reads its type, size, and metadata." },
    { step: "2. Static checks", detail: "Hashes, signatures, and file-structure rules are compared locally." },
    { step: "3. Heuristic scoring", detail: "Rules look for suspicious traits like obfuscated scripts or odd headers." },
    { step: "4. Reputation lookup", detail: "Cloud or local intelligence checks prevalence and known verdicts." },
    { step: "5. Behavior monitoring", detail: "If executed, actions like registry edits or injection are observed." },
    { step: "6. Decision and action", detail: "The engine allows, blocks, quarantines, or flags for review." },
    { step: "7. Telemetry and alerting", detail: "Events and context are logged for investigation." },
  ];
  const analysisModes = [
    {
      mode: "Static analysis",
      looks: "File content, headers, strings, hashes",
      bestFor: "Known malware and quick blocking",
      limit: "Can miss fileless or heavily obfuscated content",
    },
    {
      mode: "Behavior analysis",
      looks: "Runtime actions like process, registry, and network activity",
      bestFor: "Fileless or new variants",
      limit: "Needs execution context and good telemetry",
    },
    {
      mode: "Reputation scoring",
      looks: "Prevalence, signer trust, and cloud verdicts",
      bestFor: "New downloads and unknown files",
      limit: "Depends on connectivity and data quality",
    },
  ];
  const reputationSignals = [
    "File prevalence across the environment.",
    "First-seen timestamp (brand-new files are higher risk).",
    "Signer certificate reputation and validity.",
    "Origin source such as email, browser download, or USB.",
    "Known bad indicators from threat intelligence feeds.",
  ];
  const securityToolRoles = [
    { tool: "Antivirus / NGAV", focus: "Detects malicious files and behaviors on endpoints", note: "Blocks known threats quickly on the host." },
    { tool: "EDR", focus: "Collects rich endpoint telemetry and response actions", note: "Gives analysts deeper context for investigations." },
    { tool: "Network security", focus: "Monitors connections, domains, and traffic patterns", note: "Sees communication even when no file is present." },
    { tool: "Email security", focus: "Filters risky attachments and links", note: "Stops many threats before they reach endpoints." },
  ];
  const alertFields = [
    { field: "Detection name", desc: "The malware family or behavior category the engine matched." },
    { field: "Category", desc: "Malware, suspicious, PUA, exploit, or policy violation." },
    { field: "Severity/confidence", desc: "How risky the engine believes the activity is." },
    { field: "Action taken", desc: "Block, quarantine, clean, or detect-only." },
    { field: "File path", desc: "Where the file lived on disk." },
    { field: "Hash", desc: "A fingerprint used to search for the same file elsewhere." },
    { field: "Signer", desc: "Publisher certificate data that can confirm legitimacy." },
    { field: "Process tree", desc: "Parent and child processes tied to execution." },
    { field: "Command line", desc: "Exact parameters used to run the process." },
    { field: "User and host", desc: "Who ran it and which device was affected." },
    { field: "Network connections", desc: "Outbound destinations close to the detection time." },
  ];
  const alertActions = [
    { action: "Blocked", desc: "Execution was prevented, but the file may remain on disk." },
    { action: "Quarantined", desc: "File moved to a safe location and cannot run." },
    { action: "Cleaned/Remediated", desc: "Malicious content removed or repaired." },
    { action: "Allowed", desc: "Engine allowed the file; verify why it was permitted." },
    { action: "Detect-only", desc: "Logged for visibility without blocking, often for tuning." },
  ];
  const alertSeveritySignals = [
    "The same detection appears on multiple hosts.",
    "The alert involves privileged or admin accounts.",
    "System files or core services are involved.",
    "Suspicious network connections occur right after execution.",
    "The file shows up on a critical server or production asset.",
  ];
  const firstResponseChecklist = [
    "Read the action: blocked, quarantined, or allowed.",
    "Confirm host, user, and time of the detection.",
    "Capture the file hash and path for searching.",
    "Check the process tree for parent-child context.",
    "Look for related alerts in the same time window.",
  ];
  const commonMisconceptions = [
    "An alert does not always mean a full compromise.",
    "Quarantine is reversible; it is not the same as deletion.",
    "Cloud reputation can be unavailable in offline environments.",
    "Allowlisting is a controlled exception, not a permanent fix.",
    "No single detection method catches everything by itself.",
  ];
  const tuningLevers = [
    "Signature updates and cloud lookups",
    "Sensitivity levels for heuristics and ML",
    "PUA policy (block, warn, or allow)",
    "Exclusions and allowlists for trusted software",
    "Scheduled scan scope and cadence",
  ];
  const tuningGuardrails = [
    "Keep exclusions as narrow as possible (path, hash, signer).",
    "Require approval and document the business reason.",
    "Set expiration dates for temporary allowlists.",
    "Monitor for repeat alerts after tuning changes.",
    "Review tuning changes regularly and roll back if needed.",
  ];
  const qualityMetrics = [
    { metric: "Precision", meaning: "How many alerts are truly malicious", why: "Higher precision means less noise." },
    { metric: "Recall", meaning: "How many real threats are detected", why: "Higher recall means better coverage." },
    { metric: "False positive rate", meaning: "Benign items incorrectly flagged", why: "Lower rates reduce analyst fatigue." },
    { metric: "Mean time to detect", meaning: "How quickly threats are spotted", why: "Faster detection reduces impact." },
    { metric: "Coverage", meaning: "How much of the environment is monitored", why: "Gaps create blind spots." },
  ];
  const tradeoffNotes = [
    "Higher sensitivity catches more but can increase false positives.",
    "More exclusions reduce noise but also reduce coverage.",
    "Cloud intelligence helps with new threats but needs connectivity.",
    "Behavior monitoring improves detection but can add overhead.",
  ];
  const changeControlChecklist = [
    "Record the change, owner, and date.",
    "Validate impact on alert volume and coverage.",
    "Inform stakeholders if the change affects policy.",
    "Keep rollback steps for quick recovery.",
  ];
  const labSetupChecklist = [
    "Use isolated VMs with snapshots for easy rollback.",
    "Keep test systems off production networks.",
    "Use non-production credentials and sample data.",
    "Enable logging before running any tests.",
  ];
  const practiceExercises = [
    "Check AV status and signature update time.",
    "Run a quick scan on a clean test folder.",
    "Review quarantine history and note actions taken.",
    "Find the latest detection log entry and summarize it.",
    "If approved, test with a vendor-provided harmless sample (for example, EICAR) in a lab.",
  ];
  const practiceWriteup = [
    "What you did (steps and commands used).",
    "What you observed (alerts, logs, or changes).",
    "What evidence you captured (hashes, paths, screenshots).",
    "Your conclusion and next steps.",
  ];

  const detectionMethods = [
    {
      title: "Signature-based",
      desc: "Matches known file patterns, hashes, or byte sequences.",
      strength: "Fast and accurate for known threats.",
      gap: "Misses new or modified malware.",
    },
    {
      title: "Heuristic rules",
      desc: "Flags suspicious structures or behaviors based on rules.",
      strength: "Catches new variants with similar traits.",
      gap: "Can create false positives.",
    },
    {
      title: "Machine learning scoring",
      desc: "Scores files using patterns learned from large datasets.",
      strength: "Good coverage for new or slightly modified samples.",
      gap: "Can be harder to explain; needs tuning.",
    },
    {
      title: "Behavior monitoring",
      desc: "Watches runtime actions like process injection or registry changes.",
      strength: "Catches fileless or obfuscated threats.",
      gap: "Requires good telemetry and tuning.",
    },
    {
      title: "Memory scanning",
      desc: "Looks for malicious code in running processes.",
      strength: "Finds threats that never touch disk.",
      gap: "Needs runtime access and can be noisy.",
    },
    {
      title: "Emulation/sandbox",
      desc: "Runs code in a safe environment to observe behavior.",
      strength: "Reveals hidden behavior before full execution.",
      gap: "Can be slower and not always available locally.",
    },
    {
      title: "Reputation and cloud",
      desc: "Checks file reputation, prevalence, and cloud verdicts.",
      strength: "Fast response to emerging threats.",
      gap: "May not work offline or for new internal tools.",
    },
  ];
  const detectionPipeline = [
    "File arrives via download, email, or a USB device.",
    "On-access scan reads metadata and hashes.",
    "Static rules, heuristics, and ML scoring run.",
    "Cloud reputation checks determine if the file is known or rare.",
    "If executed, behavior and memory monitoring observe actions.",
    "A decision is made (allow, block, quarantine, or alert).",
    "Telemetry and alerts are recorded for investigation.",
  ];
  const commonAlertTypes = [
    "Malware detected (known signature match).",
    "Suspicious script or macro behavior blocked.",
    "Ransomware-like behavior (mass file changes).",
    "Credential theft or password dumping attempt.",
    "PUA detection (adware or toolbars).",
    "Exploit behavior blocked (memory or injection attempts).",
    "Policy violation (blocked by application control).",
    "Reputation alert for a new or rare file.",
  ];
  const beginnerQuestions = [
    "What file triggered the alert and where is it located?",
    "What action did the AV take (blocked, quarantined, allowed)?",
    "Which process launched it and which user ran it?",
    "Is the file signed and from a trusted vendor?",
    "Is this file new or rare in the environment?",
    "Has this file appeared on other systems?",
    "What changed right before the alert (downloads, updates, email)?",
  ];
  const falsePositiveChecklist = [
    "Verify the file hash and vendor signature.",
    "Check the file origin (download source, internal build).",
    "Compare detection name with vendor knowledge base.",
    "Check prevalence and first-seen timestamps.",
    "See if the alert repeats after reboot or removal.",
    "Confirm if other security tools alert on the same file.",
    "If safe, add allowlist with approval and document why.",
  ];

  const detectionLayers = [
    "Signatures for known malware families and hashes.",
    "Heuristics for suspicious traits and packed files.",
    "Machine learning scoring for new or modified samples.",
    "Behavior monitoring for runtime actions and persistence.",
    "Memory scanning for in-memory threats.",
    "Reputation checks for new or uncommon binaries.",
  ];

  const alertEnrichmentChecklist = [
    "SHA-256 hash and signer details",
    "Parent/child process tree and command line",
    "File origin (URL, email, removable media, or download)",
    "Network connections within a short time window",
    "Prevalence across the fleet and first-seen timestamp",
  ];

  const methodSelectionTips = [
    "Use signatures for known threats and behavior for fileless activity.",
    "Use ML scoring to catch new variants with low prevalence.",
    "Tune heuristics with allowlists for trusted internal tooling.",
    "Prefer reputation checks for newly downloaded binaries.",
    "Correlate AV alerts with EDR and network telemetry before escalation.",
    "Use sandbox or emulation results as supporting evidence when available.",
  ];

  const maintenanceChecklist = [
    "Review exclusions and allowlists on a regular cadence.",
    "Confirm real-time protection and cloud features are enabled.",
    "Validate scan schedules and update windows.",
    "Test detection workflows in a lab environment.",
    "Audit who can change policy and track approvals.",
    "Verify signature update success and failure alerts.",
  ];

  const triageNoteTemplate = [
    "Summary and severity rating",
    "Host and user context",
    "Evidence captured (hashes, paths, process tree)",
    "Actions taken and containment status",
    "Next steps and owner",
  ];

  const severityRubric = [
    { level: "Low", indicators: "Single host, low-risk PUA, no lateral movement", action: "Document, monitor, and close if validated" },
    { level: "Medium", indicators: "Suspicious behavior or unknown binary on user endpoint", action: "Contain if needed and enrich evidence" },
    { level: "High", indicators: "Multiple hosts, privileged accounts, or confirmed malware family", action: "Escalate to IR and hunt for spread" },
    { level: "Critical", indicators: "Production impact, data exfiltration, or ransomware behavior", action: "Immediate incident response and containment" },
  ];

  const falsePositiveSources = [
    "Admin and IT tools that use scripting or remote execution",
    "Packers or installers that look like obfuscation",
    "Custom internal apps with low reputation",
    "Security testing tools or lab samples",
    "Unsigned utilities in development folders",
    "Automation scripts that touch many files quickly",
    "Legacy apps with unusual behavior but known vendors",
  ];

  const escalationPacket = [
    "Alert summary with severity and timestamps",
    "Evidence bundle (hash, path, process tree)",
    "Network indicators and related connections",
    "Containment actions already taken",
    "Owner, system criticality, and business impact",
  ];

  const responseChecklist = [
    "Isolate affected hosts if malicious activity is confirmed",
    "Collect volatile data before remediation",
    "Remove persistence and validate clean state",
    "Scan for related indicators across the fleet",
    "Update detections and document lessons learned",
    "Reset credentials if compromise is suspected",
    "Notify stakeholders and document user impact",
  ];

  const labSafetyTips = [
    "Use isolated networks and disposable test VMs",
    "Avoid scanning production unless approved",
    "Never execute unknown samples on corporate devices",
    "Reset snapshots after testing to remove artifacts",
    "Use vendor-provided test files instead of real malware",
  ];

  const signals = [
    "Unexpected child processes (office app spawning script engine).",
    "Executable running from user temp or downloads.",
    "Repeated registry or scheduled task changes.",
    "Suspicious network destinations or spikes in outbound traffic.",
    "Unsigned binaries or mismatched file hashes.",
    "Browser spawning command shells or script hosts.",
    "Unusual access to security tools or credential stores.",
  ];
  const telemetrySources = [
    "Process creation logs (with command line and parent).",
    "File creation and modification events.",
    "Security and application logs.",
    "PowerShell or script engine logs.",
    "Network connection logs (destination and ports).",
    "DNS and proxy logs for outbound resolution.",
    "AV engine logs and quarantine events.",
  ];

  const artifacts = [
    "File path and hash (SHA-256)",
    "File size and timestamps",
    "Command line arguments",
    "Parent process and process tree",
    "User account and logon session",
    "Registry keys or scheduled tasks touched",
    "Network destinations and ports",
    "Alert ID and action taken",
  ];
  const simpleScenario = [
    "User opens an email attachment.",
    "The attachment drops a new executable into the Downloads folder.",
    "On-access scan flags the file as suspicious and quarantines it.",
    "EDR logs show the parent process and command line.",
    "Analyst captures the hash, path, and user details.",
    "Reputation shows the file is new and rare.",
    "Analyst checks for the same hash on other hosts.",
    "Incident response validates and documents the outcome.",
  ];

  return (
    <LearnPageLayout pageTitle="Antivirus Detection" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          {/* Sidebar Navigation */}
          {!isMobile && (
            <Grid item md={2.5}>
              {sidebarNav}
            </Grid>
          )}

          {/* Main Content */}
          <Grid item xs={12} md={9.5}>
            {/* Introduction Section */}
            <Box id="intro" sx={{ mb: 5 }}>
              <Chip
                component={Link}
                to="/learn"
                icon={<ArrowBackIcon />}
                label="Back to Learning Hub"
                clickable
                variant="outlined"
                sx={{ borderRadius: 2, mb: 2, borderColor: themeColors.border }}
              />

              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <ShieldIcon sx={{ fontSize: 42, color: themeColors.primary }} />
                <Typography
                  variant="h3"
                  sx={{
                    fontWeight: 700,
                    background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.secondary} 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  Antivirus Detection
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ color: themeColors.textMuted, mb: 2 }}>
                Antivirus detection is how security tools spot malware and risky activity on devices and servers.
              </Typography>
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
                <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                  In simple terms, antivirus tools are like security guards for your computer. They look at files and
                  programs and try to decide if something is safe or risky. They do this by comparing files to known
                  bad patterns, watching how programs behave, and checking reputation data.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted }}>
                  This page is a beginner-friendly guide to detection basics, safe checks you can run in a lab, and how
                  to document what you find without disrupting systems.
                </Typography>
              </Paper>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip icon={<BugReportIcon />} label="Signatures" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
                <Chip icon={<SearchIcon />} label="Behavior" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
                <Chip icon={<SecurityIcon />} label="Reputation" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
                <Chip icon={<WarningIcon />} label="False Positives" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
              </Box>
              <Paper sx={{ p: 3, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 2 }}>
                  What You'll Learn
                </Typography>
                <Grid container spacing={2}>
                  {beginnerObjectives.map((item) => (
                    <Grid item xs={12} sm={6} key={item}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckCircleIcon sx={{ color: themeColors.primary, fontSize: 18 }} />
                        <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{item}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Box>

            {/* Overview Section */}
            <Paper id="overview" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DashboardIcon /> Overview
              </Typography>
              
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Term</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Meaning</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {beginnerTerms.map((item) => (
                        <TableRow key={item.term}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.term}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Why Detection Matters
                </Typography>
                <List dense>
                  {[
                    "Endpoints are the first place malware appears.",
                    "Detection helps stop threats before they spread.",
                    "Good telemetry makes investigations faster and clearer.",
                    "Early alerts reduce downtime and data loss.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Basic Detection Flow
                </Typography>
                <List dense>
                  {detectionPipeline.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Detection Layers at a Glance
                </Typography>
                <List dense>
                  {detectionLayers.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* How AV Works Section */}
            <Paper id="how-av-works" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SearchIcon /> How AV Works
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                Antivirus is not a single scan. It is a series of layered checks that happen when files arrive, when they run,
                and sometimes even while they are in memory. Each layer adds context so the engine can decide whether to allow,
                block, or quarantine an item.
              </Typography>
              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                Think of it like airport security: multiple checkpoints, each looking for different signals. If one layer misses
                something, another might catch it.
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  When Scanning Happens
                </Typography>
                <List dense>
                  {scanTypes.map((item) => (
                    <ListItem key={item.title}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={item.title}
                        secondary={item.desc}
                        primaryTypographyProps={{ sx: { color: "#e2e8f0", fontWeight: 600 } }}
                        secondaryTypographyProps={{ sx: { color: themeColors.textMuted } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Inside a Scan (Step-by-step)
                </Typography>
                <List dense>
                  {scanWorkflow.map((item) => (
                    <ListItem key={item.step}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={item.step}
                        secondary={item.detail}
                        primaryTypographyProps={{ sx: { color: "#e2e8f0", fontWeight: 600 } }}
                        secondaryTypographyProps={{ sx: { color: themeColors.textMuted } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Static vs Behavior vs Reputation
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Approach</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Looks at</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Best for</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Limit</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {analysisModes.map((item) => (
                        <TableRow key={item.mode}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.mode}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.looks}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.bestFor}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.limit}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Reputation Signals (What the Cloud Uses)
                </Typography>
                <List dense>
                  {reputationSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Where AV Fits in the Security Stack
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Tool</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Focus</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Beginner Note</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {securityToolRoles.map((item) => (
                        <TableRow key={item.tool}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.tool}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.focus}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.note}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Common Misconceptions</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {commonMisconceptions.map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Detection Methods Section */}
            <Paper id="detection-methods" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon /> Detection Methods
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                Detection methods are different lenses that analyze a file or activity. No single method is perfect, so modern
                AV stacks multiple techniques to improve coverage while keeping noise manageable.
              </Typography>
              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                As a beginner, focus on the idea that each method has strengths and gaps. Good detection uses several layers.
              </Typography>
              
              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: themeColors.primary }}>Method</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>What it does</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Strength</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Limit</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {detectionMethods.map((item) => (
                      <TableRow key={item.title}>
                        <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.title}</TableCell>
                        <TableCell sx={{ color: themeColors.textMuted }}>{item.desc}</TableCell>
                        <TableCell sx={{ color: themeColors.textMuted }}>{item.strength}</TableCell>
                        <TableCell sx={{ color: themeColors.textMuted }}>{item.gap}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Simple Example
                </Typography>
                <List dense>
                  {simpleScenario.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Method Selection Tips
                </Typography>
                <List dense>
                  {methodSelectionTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>False Positives and False Negatives</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "False positives happen when a safe file is flagged as malicious.",
                      "False negatives happen when malware is missed or allowed.",
                      "Use allowlists and tuning to reduce noise without lowering coverage.",
                      "Always validate alerts with additional evidence before taking action.",
                    ].map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Alert Anatomy Section */}
            <Paper id="alert-anatomy" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <InfoIcon /> Alert Anatomy
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                An AV alert is a structured summary of what the engine saw and what it did. It is not just a yes/no verdict.
                The fields inside the alert tell you how to verify the event and decide the next step.
              </Typography>
              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                Start by confirming the action taken and the file details. Then look at process context and network activity.
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Alert Fields Explained
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Field</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Why it matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {alertFields.map((item) => (
                        <TableRow key={item.field}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.field}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Common Action Types
                </Typography>
                <List dense>
                  {alertActions.map((item) => (
                    <ListItem key={item.action}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={item.action}
                        secondary={item.desc}
                        primaryTypographyProps={{ sx: { color: "#e2e8f0", fontWeight: 600 } }}
                        secondaryTypographyProps={{ sx: { color: themeColors.textMuted } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Signals That Raise Severity
                </Typography>
                <List dense>
                  {alertSeveritySignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  First 15 Minutes Checklist
                </Typography>
                <List dense>
                  {firstResponseChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Signals and Artifacts Section */}
            <Paper id="signals-artifacts" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <ShieldIcon /> Signals and Artifacts
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 2 }}>
                Signals are small clues that something is off. One signal alone might be harmless, but several together
                paint a clearer picture. Artifacts are the concrete evidence you capture to confirm what happened.
              </Typography>
              
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Common Detection Signals
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Common Alert Types
                </Typography>
                <List dense>
                  {commonAlertTypes.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources to Check
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Evidence to Capture
                </Typography>
                <List dense>
                  {artifacts.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Alert Enrichment Checklist
                </Typography>
                <List dense>
                  {alertEnrichmentChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Tuning and Metrics Section */}
            <Paper id="tuning-metrics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon /> Tuning & Metrics
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                Detection tuning is about balancing protection with noise. Every environment is different, so teams adjust
                settings, allowlists, and policies to keep alerts useful and actionable.
              </Typography>
              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                The goal is not to remove all alerts, but to make sure each alert is worth investigating.
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Common Tuning Levers
                </Typography>
                <List dense>
                  {tuningLevers.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Quality Metrics in Plain Language
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Metric</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Meaning</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Why it matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {qualityMetrics.map((item) => (
                        <TableRow key={item.metric}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{item.metric}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.meaning}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{item.why}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Tradeoffs to Remember
                </Typography>
                <List dense>
                  {tradeoffNotes.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Safe Exclusion Guardrails
                </Typography>
                <List dense>
                  {tuningGuardrails.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Change Control Checklist
                </Typography>
                <List dense>
                  {changeControlChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Platform Checks Section */}
            <Paper id="platform-checks" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon /> Platform Checks
              </Typography>
              
              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Windows Defender (Safe Checks)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="powershell"
                    code={`# Check Defender status
Get-MpComputerStatus

# View configuration (read-only)
Get-MpPreference

# Update signatures (safe on lab systems)
Update-MpSignature

# Run a quick scan (lab only)
Start-MpScan -ScanType QuickScan`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Linux (ClamAV Basics)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Check ClamAV version
clamscan --version

# Scan a lab folder only
clamscan -r /path/to/lab-samples

# Update signatures (if configured)
freshclam`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>macOS (Basic Visibility)</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Check XProtect status (built-in protection)
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString

# Gatekeeper status
spctl --status

# List system extensions (read-only)
systemextensionsctl list`}
                  />
                </AccordionDetails>
              </Accordion>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Safe Baseline Checks
                </Typography>
                <List dense>
                  {[
                    "Confirm AV is enabled and signatures are current.",
                    "Check quarantine history for recent detections.",
                    "Validate scanning schedule and exclusions.",
                    "Record the tool version and last update time.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Maintenance Checklist
                </Typography>
                <List dense>
                  {maintenanceChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Lab Safety Tips
                </Typography>
                <List dense>
                  {labSafetyTips.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Practice Lab Section */}
            <Paper id="practice-lab" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon /> Practice Lab
              </Typography>
              <Typography variant="body1" sx={{ color: "#e2e8f0", mb: 1 }}>
                The safest way to learn AV detection is in a controlled lab. Use disposable virtual machines and harmless
                test files so you can observe detections without risking production systems.
              </Typography>
              <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 3 }}>
                These exercises focus on observing, documenting, and understanding alerts rather than triggering real malware.
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Lab Setup Checklist
                </Typography>
                <List dense>
                  {labSetupChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Safe Exercises (Beginner Friendly)
                </Typography>
                <List dense>
                  {practiceExercises.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Mini Write-up Template
                </Typography>
                <List dense>
                  {practiceWriteup.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Triage and Response Section */}
            <Paper id="triage-response" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <AssignmentIcon /> Triage and Response
              </Typography>
              
              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Triage Workflow (Beginner Friendly)
                </Typography>
                <List dense>
                  {[
                    "Confirm alert details (host, user, process, file path).",
                    "Collect evidence: hash, command line, parent process.",
                    "Check if the file is known and signed by a trusted vendor.",
                    "Contain if needed: isolate host or stop the process.",
                    "Escalate to incident response with clear notes.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Severity Rubric
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: themeColors.primary }}>Level</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Indicators</TableCell>
                        <TableCell sx={{ color: themeColors.primary }}>Action</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {severityRubric.map((row) => (
                        <TableRow key={row.level}>
                          <TableCell sx={{ color: "#e2e8f0", fontWeight: 600 }}>{row.level}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{row.indicators}</TableCell>
                          <TableCell sx={{ color: themeColors.textMuted }}>{row.action}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Beginner Questions
                </Typography>
                <List dense>
                  {beginnerQuestions.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  False Positive Checklist
                </Typography>
                <List dense>
                  {falsePositiveChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Common False Positive Sources
                </Typography>
                <List dense>
                  {falsePositiveSources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Triage Note Template
                </Typography>
                <List dense>
                  {triageNoteTemplate.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Response Checklist
                </Typography>
                <List dense>
                  {responseChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Escalation Packet
                </Typography>
                <List dense>
                  {escalationPacket.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ color: themeColors.primary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  When to Escalate
                </Typography>
                <List dense>
                  {[
                    "Multiple hosts showing the same alert.",
                    "Suspicious network connections or data exfiltration.",
                    "System files or privileged accounts involved.",
                    "Repeated detections after cleaning.",
                    "Any detection on production servers.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <WarningIcon sx={{ color: themeColors.secondary }} fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Paper>

            {/* Quiz Section */}
            <Paper
              id="quiz-section"
              sx={{
                p: 4,
                mb: 5,
                borderRadius: 3,
                border: `1px solid ${themeColors.border}`,
                bgcolor: `${themeColors.primary}08`,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
                Knowledge Check
              </Typography>
              <QuizSection
                questions={quizQuestions}
                accentColor={QUIZ_ACCENT_COLOR}
                title="Antivirus Detection Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Mobile Drawer */}
        <Drawer
          anchor="left"
          open={mobileNavOpen}
          onClose={() => setMobileNavOpen(false)}
          PaperProps={{ sx: { bgcolor: themeColors.bgCard, p: 2, width: 280 } }}
        >
          {sidebarNav}
        </Drawer>

        {/* Mobile FABs */}
        {isMobile && (
          <>
            <Fab
              color="primary"
              onClick={() => setMobileNavOpen(true)}
              sx={{ position: "fixed", bottom: 80, right: 16, bgcolor: themeColors.primary }}
            >
              <MenuIcon />
            </Fab>
            <Fab
              size="small"
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              sx={{ position: "fixed", bottom: 24, right: 16, bgcolor: themeColors.bgCard }}
            >
              <KeyboardArrowUpIcon />
            </Fab>
          </>
        )}
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default AntiVirusDetectionPage;
