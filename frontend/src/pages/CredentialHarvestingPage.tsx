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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import SearchIcon from "@mui/icons-material/Search";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ShieldIcon from "@mui/icons-material/Shield";
import BuildIcon from "@mui/icons-material/Build";
import QuizIcon from "@mui/icons-material/Quiz";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import SchoolIcon from "@mui/icons-material/School";
import StorageIcon from "@mui/icons-material/Storage";
import ScienceIcon from "@mui/icons-material/Science";
import { Link, useNavigate } from "react-router-dom";

const themeColors = {
  primary: "#a855f7",
  primaryLight: "#c084fc",
  secondary: "#ec4899",
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
  { id: "intro", label: "Introduction", icon: <VpnKeyIcon /> },
  { id: "overview", label: "Overview", icon: <SecurityIcon /> },
  { id: "methods", label: "Methods", icon: <WarningIcon /> },
  { id: "storage-risks", label: "Storage & Risks", icon: <StorageIcon /> },
  { id: "detection", label: "Detection", icon: <SearchIcon /> },
  { id: "prevention", label: "Prevention", icon: <ShieldIcon /> },
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
        border: "1px solid rgba(168, 85, 247, 0.3)",
      }}
    >
      <Box sx={{ position: "absolute", top: 8, right: 8, display: "flex", gap: 1 }}>
        <Chip label={language} size="small" sx={{ bgcolor: "#a855f7", color: "#0b1020" }} />
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
const QUIZ_ACCENT_COLOR = "#a855f7";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Basics",
    question: "What is credential harvesting?",
    options: [
      "Collecting authentication secrets such as passwords or tokens",
      "Encrypting files for backup",
      "Patching operating systems",
      "Scanning for open ports only",
    ],
    correctAnswer: 0,
    explanation: "Credential harvesting focuses on obtaining passwords, hashes, or tokens.",
  },
  {
    id: 2,
    topic: "Basics",
    question: "Why are credentials a high-value target?",
    options: [
      "They provide access without needing new exploits",
      "They automatically grant physical access",
      "They disable all logging",
      "They are always encrypted and unusable",
    ],
    correctAnswer: 0,
    explanation: "Valid credentials enable access to systems and data.",
  },
  {
    id: 3,
    topic: "Phishing",
    question: "Phishing typically attempts to:",
    options: [
      "Trick users into revealing credentials",
      "Patch software remotely",
      "Disable multi-factor authentication",
      "Delete system logs",
    ],
    correctAnswer: 0,
    explanation: "Phishing uses social engineering to capture credentials.",
  },
  {
    id: 4,
    topic: "Phishing",
    question: "A common defense against phishing is:",
    options: [
      "User awareness training and MFA",
      "Disabling all email",
      "Allowing shared passwords",
      "Removing antivirus",
    ],
    correctAnswer: 0,
    explanation: "Training and MFA reduce the impact of stolen passwords.",
  },
  {
    id: 5,
    topic: "Dumping",
    question: "Credential dumping refers to:",
    options: [
      "Extracting stored or in-memory credentials from a system",
      "Resetting a user's password",
      "Rotating API keys",
      "Encrypting local files",
    ],
    correctAnswer: 0,
    explanation: "Credential dumping extracts secrets from local storage or memory.",
  },
  {
    id: 6,
    topic: "Windows",
    question: "Which Windows process commonly stores credentials in memory?",
    options: [
      "LSASS",
      "explorer.exe",
      "svchost.exe",
      "spoolsv.exe",
    ],
    correctAnswer: 0,
    explanation: "LSASS holds authentication data in memory.",
  },
  {
    id: 7,
    topic: "Windows",
    question: "Why is LSASS access restricted?",
    options: [
      "It contains sensitive credential material",
      "It controls DNS resolution",
      "It manages disk encryption",
      "It updates system drivers",
    ],
    correctAnswer: 0,
    explanation: "LSASS contains secrets that can be abused for movement.",
  },
  {
    id: 8,
    topic: "Windows",
    question: "What is the SAM database used for?",
    options: [
      "Storing local account password hashes",
      "Storing browser history",
      "Storing network routes",
      "Storing printer configs",
    ],
    correctAnswer: 0,
    explanation: "SAM stores local account credentials.",
  },
  {
    id: 9,
    topic: "Linux",
    question: "Where are password hashes typically stored on Linux?",
    options: [
      "/etc/shadow",
      "/etc/passwd only",
      "/var/log/messages",
      "/tmp/credentials",
    ],
    correctAnswer: 0,
    explanation: "/etc/shadow stores password hashes on Linux.",
  },
  {
    id: 10,
    topic: "Browsers",
    question: "Why are browsers a common credential source?",
    options: [
      "They store saved passwords and session cookies",
      "They always store data in plain text",
      "They disable encryption by default",
      "They cannot be audited",
    ],
    correctAnswer: 0,
    explanation: "Saved passwords and cookies can be reused if stolen.",
  },
  {
    id: 11,
    topic: "Tokens",
    question: "Session tokens are valuable because they:",
    options: [
      "Can allow access without a password",
      "Always expire immediately",
      "Require physical access to use",
      "Cannot be reused",
    ],
    correctAnswer: 0,
    explanation: "Session tokens can bypass password entry if valid.",
  },
  {
    id: 12,
    topic: "Tokens",
    question: "Token theft is especially risky when:",
    options: [
      "Sessions are long-lived and not tied to devices",
      "Tokens expire every minute",
      "Tokens are hardware-bound",
      "Tokens are never used",
    ],
    correctAnswer: 0,
    explanation: "Long-lived tokens increase the impact of theft.",
  },
  {
    id: 13,
    topic: "Techniques",
    question: "Credential stuffing is:",
    options: [
      "Reusing leaked credentials across multiple services",
      "Trying many passwords for one account",
      "Resetting passwords through email",
      "Creating new accounts with strong passwords",
    ],
    correctAnswer: 0,
    explanation: "Stuffing uses known credentials across many systems.",
  },
  {
    id: 14,
    topic: "Techniques",
    question: "Password spraying is:",
    options: [
      "Trying a few passwords across many accounts",
      "Trying many passwords against one account",
      "Changing passwords for all users",
      "Resetting passwords via SMS",
    ],
    correctAnswer: 0,
    explanation: "Spraying avoids lockouts by limiting attempts per account.",
  },
  {
    id: 15,
    topic: "Techniques",
    question: "Keylogging is used to:",
    options: [
      "Capture keystrokes to steal credentials",
      "Block all keyboard input",
      "Encrypt files at rest",
      "Reset user passwords",
    ],
    correctAnswer: 0,
    explanation: "Keyloggers capture typed credentials.",
  },
  {
    id: 16,
    topic: "Storage",
    question: "Why are configuration files risky?",
    options: [
      "They may contain plaintext secrets",
      "They always delete logs",
      "They cannot be read by admins",
      "They are encrypted by default",
    ],
    correctAnswer: 0,
    explanation: "Config files often hold API keys or passwords.",
  },
  {
    id: 17,
    topic: "Storage",
    question: "Why are SSH private keys sensitive?",
    options: [
      "They can authenticate without a password",
      "They always expire instantly",
      "They are public data",
      "They cannot be used remotely",
    ],
    correctAnswer: 0,
    explanation: "Private keys enable access if stolen.",
  },
  {
    id: 18,
    topic: "Cloud",
    question: "Cloud access keys are valuable because they:",
    options: [
      "Provide programmatic access to cloud resources",
      "Disable network logging",
      "Force MFA on all users",
      "Only work on local systems",
    ],
    correctAnswer: 0,
    explanation: "Cloud keys can enable access to storage and compute.",
  },
  {
    id: 19,
    topic: "Detection",
    question: "Which signal can indicate credential stuffing?",
    options: [
      "Many failed logins across many accounts",
      "Single login from a known device",
      "System reboot events",
      "DNS cache flushes",
    ],
    correctAnswer: 0,
    explanation: "Stuffing produces widespread failed logins.",
  },
  {
    id: 20,
    topic: "Detection",
    question: "What is an impossible travel alert?",
    options: [
      "Logins from distant locations in an unrealistic time window",
      "A system update outside business hours",
      "A workstation reboot",
      "A password change event",
    ],
    correctAnswer: 0,
    explanation: "Impossible travel indicates potential credential misuse.",
  },
  {
    id: 21,
    topic: "Detection",
    question: "What does MFA help prevent?",
    options: [
      "Unauthorized access using stolen passwords",
      "System crashes",
      "Disk failures",
      "Network congestion",
    ],
    correctAnswer: 0,
    explanation: "MFA adds a second factor beyond passwords.",
  },
  {
    id: 22,
    topic: "Detection",
    question: "Why monitor for access to credential stores?",
    options: [
      "Access can indicate credential harvesting activity",
      "It is required for normal browsing",
      "It happens only during updates",
      "It never occurs on endpoints",
    ],
    correctAnswer: 0,
    explanation: "Unexpected access to credential stores is suspicious.",
  },
  {
    id: 23,
    topic: "Windows",
    question: "Credential Guard helps by:",
    options: [
      "Isolating secrets from user-mode processes",
      "Disabling all Windows logons",
      "Encrypting the hard drive only",
      "Removing all event logs",
    ],
    correctAnswer: 0,
    explanation: "Credential Guard protects secrets from many attacks.",
  },
  {
    id: 24,
    topic: "Windows",
    question: "Why disable WDigest?",
    options: [
      "It can store plaintext credentials in memory",
      "It is required for Kerberos",
      "It enables MFA",
      "It patches the OS",
    ],
    correctAnswer: 0,
    explanation: "WDigest may keep plaintext credentials if enabled.",
  },
  {
    id: 25,
    topic: "Windows",
    question: "Why is LAPS helpful for credential security?",
    options: [
      "It rotates local admin passwords uniquely per host",
      "It disables all local admin accounts",
      "It removes the need for patching",
      "It blocks all network access",
    ],
    correctAnswer: 0,
    explanation: "Unique local passwords reduce reuse across machines.",
  },
  {
    id: 26,
    topic: "Linux",
    question: "Why restrict read access to /etc/shadow?",
    options: [
      "It prevents unauthorized hash access",
      "It speeds up boot time",
      "It disables SSH",
      "It removes user accounts",
    ],
    correctAnswer: 0,
    explanation: "Protecting /etc/shadow limits offline cracking.",
  },
  {
    id: 27,
    topic: "Storage",
    question: "Secrets in code repositories are dangerous because:",
    options: [
      "They can be copied and reused by anyone with access",
      "They expire instantly",
      "They never work outside development",
      "They are always encrypted",
    ],
    correctAnswer: 0,
    explanation: "Hard-coded secrets can be reused across environments.",
  },
  {
    id: 28,
    topic: "Storage",
    question: "Why is secret rotation important after exposure?",
    options: [
      "It invalidates stolen credentials",
      "It reduces log volume",
      "It stops all logins",
      "It disables MFA",
    ],
    correctAnswer: 0,
    explanation: "Rotation invalidates leaked secrets.",
  },
  {
    id: 29,
    topic: "Detection",
    question: "Which log source is key for login anomaly detection?",
    options: [
      "Authentication logs",
      "Printer logs",
      "BIOS logs",
      "Display logs",
    ],
    correctAnswer: 0,
    explanation: "Auth logs capture login attempts and failures.",
  },
  {
    id: 30,
    topic: "Techniques",
    question: "Credential reuse across systems increases risk because:",
    options: [
      "A single compromise can grant access to many systems",
      "It improves security",
      "It prevents password sprays",
      "It disables logging",
    ],
    correctAnswer: 0,
    explanation: "Reuse enables rapid movement using the same credentials.",
  },
  {
    id: 31,
    topic: "Tokens",
    question: "Why are refresh tokens sensitive?",
    options: [
      "They can be used to obtain new access tokens",
      "They only work once",
      "They are public by default",
      "They cannot be revoked",
    ],
    correctAnswer: 0,
    explanation: "Refresh tokens extend session life if stolen.",
  },
  {
    id: 32,
    topic: "Phishing",
    question: "Spearphishing differs from phishing because it is:",
    options: [
      "Targeted to a specific individual or group",
      "Always sent from internal addresses",
      "Limited to SMS only",
      "Guaranteed to bypass MFA",
    ],
    correctAnswer: 0,
    explanation: "Spearphishing is targeted and personalized.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Why monitor for new MFA bypasses?",
    options: [
      "They can allow use of stolen passwords",
      "They increase password length",
      "They reduce log volume",
      "They disable VPNs",
    ],
    correctAnswer: 0,
    explanation: "MFA bypasses increase risk from harvested credentials.",
  },
  {
    id: 34,
    topic: "Windows",
    question: "What is a sign of possible credential dumping?",
    options: [
      "Unexpected access to LSASS memory",
      "Normal login activity",
      "Routine system updates",
      "Patch installation events",
    ],
    correctAnswer: 0,
    explanation: "Access to LSASS often indicates dumping attempts.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "Why is credential access to browser stores suspicious?",
    options: [
      "It can indicate theft of saved credentials",
      "It is required for OS updates",
      "It is used only by the kernel",
      "It occurs at system boot only",
    ],
    correctAnswer: 0,
    explanation: "Browser stores hold saved credentials and cookies.",
  },
  {
    id: 36,
    topic: "Defense",
    question: "What is a best practice for password policy?",
    options: [
      "Use long, unique passwords and ban common ones",
      "Allow shared passwords",
      "Disable MFA",
      "Avoid password rotation after incidents",
    ],
    correctAnswer: 0,
    explanation: "Strong unique passwords reduce guessing and reuse risk.",
  },
  {
    id: 37,
    topic: "Defense",
    question: "Why use password managers?",
    options: [
      "They help generate and store unique passwords",
      "They disable logging",
      "They remove MFA requirements",
      "They expose all passwords to users",
    ],
    correctAnswer: 0,
    explanation: "Password managers reduce reuse and encourage stronger passwords.",
  },
  {
    id: 38,
    topic: "Defense",
    question: "Why limit local admin rights?",
    options: [
      "It reduces access to credential stores and dumping tools",
      "It increases credential reuse",
      "It disables endpoint monitoring",
      "It prevents patching",
    ],
    correctAnswer: 0,
    explanation: "Fewer admins reduces access to sensitive stores.",
  },
  {
    id: 39,
    topic: "Defense",
    question: "What is a key response step after credential theft?",
    options: [
      "Reset and rotate affected credentials",
      "Ignore the event",
      "Disable logs",
      "Remove all user accounts",
    ],
    correctAnswer: 0,
    explanation: "Rotate credentials to invalidate stolen secrets.",
  },
  {
    id: 40,
    topic: "Defense",
    question: "Why monitor for logins from new devices?",
    options: [
      "New devices can indicate stolen credentials",
      "New devices always mean patching",
      "New devices improve trust",
      "New devices reduce risk",
    ],
    correctAnswer: 0,
    explanation: "Unrecognized devices can signal compromise.",
  },
  {
    id: 41,
    topic: "Defense",
    question: "Why is device binding for tokens helpful?",
    options: [
      "It limits token reuse on other devices",
      "It disables encryption",
      "It removes the need for MFA",
      "It blocks logging",
    ],
    correctAnswer: 0,
    explanation: "Device binding reduces token theft impact.",
  },
  {
    id: 42,
    topic: "Detection",
    question: "Which of the following suggests password spraying?",
    options: [
      "Many accounts with one or two failed attempts each",
      "One account with thousands of attempts",
      "Only successful logons",
      "Only local logons",
    ],
    correctAnswer: 0,
    explanation: "Spraying spreads attempts across many accounts.",
  },
  {
    id: 43,
    topic: "Storage",
    question: "Why are environment files (like .env) risky?",
    options: [
      "They often contain API keys or secrets",
      "They only store comments",
      "They cannot be read by users",
      "They are encrypted by default",
    ],
    correctAnswer: 0,
    explanation: "Environment files can hold sensitive secrets.",
  },
  {
    id: 44,
    topic: "Detection",
    question: "Why monitor for credential access tools on endpoints?",
    options: [
      "They can indicate harvesting activity",
      "They improve system stability",
      "They reduce alert volume",
      "They are required for normal OS updates",
    ],
    correctAnswer: 0,
    explanation: "Unexpected credential tools are suspicious.",
  },
  {
    id: 45,
    topic: "Basics",
    question: "Which is NOT a credential harvesting method?",
    options: [
      "Disk defragmentation",
      "Phishing",
      "Keylogging",
      "Credential dumping",
    ],
    correctAnswer: 0,
    explanation: "Disk defragmentation is unrelated to credential harvesting.",
  },
  {
    id: 46,
    topic: "Detection",
    question: "Why review access to password manager databases?",
    options: [
      "Compromise can expose many credentials at once",
      "Managers are never attacked",
      "Managers store only public data",
      "Managers disable MFA",
    ],
    correctAnswer: 0,
    explanation: "Password managers can be high-value targets.",
  },
  {
    id: 47,
    topic: "Storage",
    question: "Why is storing passwords in plain text risky?",
    options: [
      "They can be read and reused directly",
      "They are always encrypted",
      "They cannot be copied",
      "They are stored only in memory",
    ],
    correctAnswer: 0,
    explanation: "Plain text passwords provide immediate access.",
  },
  {
    id: 48,
    topic: "Cloud",
    question: "Why monitor access to cloud metadata endpoints?",
    options: [
      "They can yield temporary cloud credentials",
      "They are only used for backups",
      "They are always blocked",
      "They contain OS patches",
    ],
    correctAnswer: 0,
    explanation: "Metadata endpoints can provide credentials for cloud services.",
  },
  {
    id: 49,
    topic: "Defense",
    question: "Why enforce MFA on VPN access?",
    options: [
      "It reduces risk of stolen password access",
      "It disables logging",
      "It removes segmentation",
      "It prevents updates",
    ],
    correctAnswer: 0,
    explanation: "MFA reduces the impact of stolen VPN credentials.",
  },
  {
    id: 50,
    topic: "Defense",
    question: "Which is a safe lab practice for credential security training?",
    options: [
      "Use synthetic accounts and fake secrets",
      "Use production credentials",
      "Disable logging to avoid alerts",
      "Store real passwords in files",
    ],
    correctAnswer: 0,
    explanation: "Always use synthetic data in labs.",
  },
  {
    id: 51,
    topic: "Detection",
    question: "What indicates possible token theft?",
    options: [
      "Session usage from a new device without re-auth",
      "Normal password changes",
      "Scheduled reboots",
      "Routine backups",
    ],
    correctAnswer: 0,
    explanation: "Token reuse from a new device suggests theft.",
  },
  {
    id: 52,
    topic: "Defense",
    question: "Why enable conditional access policies?",
    options: [
      "They add context checks for logins",
      "They disable MFA",
      "They remove all logs",
      "They force password reuse",
    ],
    correctAnswer: 0,
    explanation: "Conditional access adds device, location, and risk checks.",
  },
  {
    id: 53,
    topic: "Windows",
    question: "Why are DPAPI secrets important?",
    options: [
      "They protect stored credentials and browser data",
      "They disable encryption",
      "They remove user accounts",
      "They delete logs",
    ],
    correctAnswer: 0,
    explanation: "DPAPI protects local secret storage on Windows.",
  },
  {
    id: 54,
    topic: "Windows",
    question: "Why is restricting debug privileges helpful?",
    options: [
      "It reduces the ability to access LSASS memory",
      "It disables all user accounts",
      "It increases patching",
      "It removes MFA",
    ],
    correctAnswer: 0,
    explanation: "Debug privileges enable access to sensitive processes.",
  },
  {
    id: 55,
    topic: "Detection",
    question: "What is a sign of credential spraying in logs?",
    options: [
      "Many failed logins across many users from one IP",
      "One successful login only",
      "System boot events",
      "Patch management logs",
    ],
    correctAnswer: 0,
    explanation: "Spraying yields many failures across many users.",
  },
  {
    id: 56,
    topic: "Defense",
    question: "Why use account lockout policies?",
    options: [
      "They slow brute-force attempts",
      "They disable MFA",
      "They prevent logging",
      "They force password reuse",
    ],
    correctAnswer: 0,
    explanation: "Lockouts limit brute-force success.",
  },
  {
    id: 57,
    topic: "Defense",
    question: "Why is least privilege useful for credentials?",
    options: [
      "It reduces access to sensitive credential stores",
      "It disables updates",
      "It increases reuse",
      "It removes segmentation",
    ],
    correctAnswer: 0,
    explanation: "Least privilege limits access to credential material.",
  },
  {
    id: 58,
    topic: "Detection",
    question: "Which telemetry can help detect keylogging?",
    options: [
      "Endpoint behavior analytics and process monitoring",
      "Only DNS logs",
      "Only firewall logs",
      "Only DHCP logs",
    ],
    correctAnswer: 0,
    explanation: "Process monitoring can reveal suspicious keylogging tools.",
  },
  {
    id: 59,
    topic: "Defense",
    question: "Why review browser extension inventories?",
    options: [
      "Malicious extensions can steal credentials",
      "Extensions disable logging",
      "Extensions are always safe",
      "Extensions only affect updates",
    ],
    correctAnswer: 0,
    explanation: "Extensions can access or steal credentials.",
  },
  {
    id: 60,
    topic: "Basics",
    question: "Which technique relies on reused passwords across services?",
    options: [
      "Credential stuffing",
      "Keylogging",
      "Disk imaging",
      "Patch management",
    ],
    correctAnswer: 0,
    explanation: "Stuffing uses known credentials across sites.",
  },
  {
    id: 61,
    topic: "Cloud",
    question: "Why is access key rotation important in cloud environments?",
    options: [
      "It reduces the impact of leaked keys",
      "It disables cloud logging",
      "It increases storage capacity",
      "It removes the need for MFA",
    ],
    correctAnswer: 0,
    explanation: "Rotation invalidates compromised keys.",
  },
  {
    id: 62,
    topic: "Defense",
    question: "Why use passwordless authentication where possible?",
    options: [
      "It reduces reliance on passwords that can be stolen",
      "It disables MFA",
      "It prevents logging",
      "It guarantees admin rights",
    ],
    correctAnswer: 0,
    explanation: "Passwordless options reduce theft risk.",
  },
  {
    id: 63,
    topic: "Detection",
    question: "Why is monitoring OAuth consent important?",
    options: [
      "Malicious apps can gain access via tokens",
      "OAuth only controls printers",
      "OAuth disables MFA",
      "OAuth is unrelated to credentials",
    ],
    correctAnswer: 0,
    explanation: "OAuth abuse can grant attackers token access.",
  },
  {
    id: 64,
    topic: "Storage",
    question: "Why is storing secrets in code comments risky?",
    options: [
      "They can be easily discovered and reused",
      "They are encrypted automatically",
      "They require admin access to read",
      "They are deleted on reboot",
    ],
    correctAnswer: 0,
    explanation: "Comments may leak secrets to anyone reading the code.",
  },
  {
    id: 65,
    topic: "Detection",
    question: "Why alert on logins from new geolocations?",
    options: [
      "They can indicate stolen credentials",
      "They always indicate normal travel",
      "They are required for updates",
      "They indicate printer usage",
    ],
    correctAnswer: 0,
    explanation: "New geolocations can indicate credential misuse.",
  },
  {
    id: 66,
    topic: "Defense",
    question: "Why use conditional access with device compliance?",
    options: [
      "It blocks logins from unmanaged or risky devices",
      "It removes all password policies",
      "It disables logging",
      "It increases reuse",
    ],
    correctAnswer: 0,
    explanation: "Device compliance reduces the risk of stolen credentials.",
  },
  {
    id: 67,
    topic: "Windows",
    question: "Why are NTLM hashes sensitive?",
    options: [
      "They can be used for authentication in some scenarios",
      "They are always random and useless",
      "They cannot be reused",
      "They prevent password changes",
    ],
    correctAnswer: 0,
    explanation: "NTLM hashes can be abused for authentication in some contexts.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Why enable alerting on account lockouts?",
    options: [
      "Lockouts can indicate brute force or spraying",
      "Lockouts are always normal",
      "Lockouts indicate patching",
      "Lockouts disable MFA",
    ],
    correctAnswer: 0,
    explanation: "Lockouts are a strong signal of attack attempts.",
  },
  {
    id: 69,
    topic: "Basics",
    question: "Which is a common credential source in CI/CD systems?",
    options: [
      "Pipeline secrets and environment variables",
      "DNS cache files",
      "Printer spool files",
      "System restore points",
    ],
    correctAnswer: 0,
    explanation: "CI/CD pipelines store secrets for deployments.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "Why scan repositories for secrets?",
    options: [
      "To detect accidental leaks of credentials",
      "To disable version control",
      "To stop logging",
      "To remove patching",
    ],
    correctAnswer: 0,
    explanation: "Secret scanning finds accidental credential exposure.",
  },
  {
    id: 71,
    topic: "Detection",
    question: "What is a red flag in authentication logs?",
    options: [
      "Multiple failed logins followed by a success",
      "A single successful login",
      "A logout event",
      "A password change by the user",
    ],
    correctAnswer: 0,
    explanation: "Failures followed by success can indicate guessing.",
  },
  {
    id: 72,
    topic: "Defense",
    question: "Why use short session lifetimes for sensitive apps?",
    options: [
      "It reduces the value of stolen tokens",
      "It disables MFA",
      "It prevents logging",
      "It increases password reuse",
    ],
    correctAnswer: 0,
    explanation: "Short sessions limit token replay windows.",
  },
  {
    id: 73,
    topic: "Defense",
    question: "Why should admins use separate accounts for daily use?",
    options: [
      "To limit exposure of privileged credentials",
      "To disable auditing",
      "To remove MFA requirements",
      "To speed up logins",
    ],
    correctAnswer: 0,
    explanation: "Separate accounts reduce exposure of privileged creds.",
  },
  {
    id: 74,
    topic: "Detection",
    question: "What does abnormal token usage often indicate?",
    options: [
      "Potential session hijacking",
      "Routine system maintenance",
      "Disk cleanup",
      "OS upgrades",
    ],
    correctAnswer: 0,
    explanation: "Unexpected token use can signal hijacking.",
  },
  {
    id: 75,
    topic: "Basics",
    question: "Which statement best summarizes credential harvesting risk?",
    options: [
      "Stolen credentials can enable broad access with minimal exploits",
      "Credentials are never reusable",
      "Credentials only work locally",
      "Credentials cannot be detected in logs",
    ],
    correctAnswer: 0,
    explanation: "Credentials enable access across systems when reused.",
  },
];

const CredentialHarvestingPage: React.FC = () => {
  const navigate = useNavigate();
  const muiTheme = useTheme();
  const isMobile = useMediaQuery(muiTheme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("intro");

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth" });
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

  const sidebarNav = (
    <Box sx={{ p: 2 }}>
      <Typography variant="overline" sx={{ color: themeColors.textMuted, fontWeight: 600, mb: 2, display: "block" }}>
        On This Page
      </Typography>
      <Box sx={{ mb: 2 }}>
        <LinearProgress
          variant="determinate"
          value={((sectionNavItems.findIndex((item) => item.id === activeSection) + 1) / sectionNavItems.length) * 100}
          sx={{ height: 4, borderRadius: 2, bgcolor: "rgba(168,85,247,0.2)", "& .MuiLinearProgress-bar": { bgcolor: themeColors.primary } }}
        />
      </Box>
      <List dense sx={{ p: 0 }}>
        {sectionNavItems.map((item) => (
          <ListItem
            key={item.id}
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 1,
              mb: 0.5,
              cursor: "pointer",
              bgcolor: activeSection === item.id ? alpha(themeColors.primary, 0.15) : "transparent",
              borderLeft: activeSection === item.id ? `3px solid ${themeColors.primary}` : "3px solid transparent",
              "&:hover": { bgcolor: alpha(themeColors.primary, 0.1) },
            }}
          >
            <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText
              primary={item.label}
              sx={{ "& .MuiListItemText-primary": { fontSize: "0.85rem", fontWeight: activeSection === item.id ? 600 : 400, color: activeSection === item.id ? themeColors.primary : themeColors.textMuted } }}
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );

  const pageContext = `This page covers credential harvesting concepts and defense strategies. Topics include harvesting methods (phishing, browser/password manager abuse, credential dumping, keylogging, token/ticket theft, secrets in files, legacy protocol abuse, password spraying), credential storage locations (Windows Credential Manager, LSASS memory, browser profiles, local files, SSH keys, CI/CD secrets, cloud access keys), detection signals and behavior indicators, telemetry sources, prevention strategies, and response actions. The page focuses on defensive awareness with safe, read-only checks and beginner-friendly lab exercises.`;

  const objectives = [
    "Explain credential harvesting in simple terms.",
    "Recognize common harvesting techniques at a high level.",
    "Identify sensitive storage locations and risks.",
    "Review basic detection signals and logging sources.",
    "Practice safe, read-only checks in a lab.",
  ];
  const beginnerPath = [
    "1) Read the glossary so the terms make sense.",
    "2) Learn where credentials usually live (browsers, vaults, files).",
    "3) Review the high-level methods without touching real data.",
    "4) Run safe checks and note what logs are available.",
    "5) Write a short report with risks and prevention ideas.",
  ];
  const whyHard = [
    "Credentials are used everywhere, so normal activity looks similar to attacks.",
    "Many systems store credentials for convenience, creating more exposure.",
    "Attackers may use cloud logins with no malware on the device.",
  ];
  const misconceptions = [
    {
      myth: "Credential harvesting always means someone installed malware.",
      reality: "It can be as simple as a fake login page or a reused password.",
    },
    {
      myth: "MFA stops all credential attacks.",
      reality: "MFA helps a lot, but attackers may still steal tokens or approve prompts.",
    },
    {
      myth: "Only admins are targeted.",
      reality: "Any account can be a stepping stone to higher access.",
    },
  ];
  const roles = [
    { role: "SOC analyst", focus: "Triage alerts and correlate login events." },
    { role: "Blue team", focus: "Harden systems and reduce credential exposure." },
    { role: "IT admin", focus: "Enforce MFA and manage password policies." },
    { role: "DevOps", focus: "Remove secrets from repos and pipelines." },
  ];
  const whatItIsNot = [
    "It is not penetration testing; this page avoids offensive instructions.",
    "It is not collecting real passwords in training environments.",
    "It is not a single tool or product; it is a set of risks and behaviors.",
  ];

  const glossary = [
    { term: "Credential", desc: "A username, password, token, or key used to authenticate." },
    { term: "Harvesting", desc: "Collecting credentials from systems or users." },
    { term: "Phishing", desc: "Tricking users into entering credentials on fake pages." },
    { term: "Memory scraping", desc: "Attempting to read credentials from running processes." },
    { term: "Credential vault", desc: "Secure storage for passwords and tokens." },
    { term: "MFA", desc: "Multi-factor authentication, a second verification step." },
  ];
  const credentialSources = [
    { source: "User input", desc: "Typing into login forms, terminals, or prompts." },
    { source: "Saved storage", desc: "Browsers, vaults, or cached credentials." },
    { source: "Memory", desc: "Credentials temporarily present while apps run." },
    { source: "Files", desc: "Configs, scripts, or notes with secrets." },
    { source: "Network", desc: "Captured tokens or insecure transfers." },
  ];
  const credentialTypes = [
    { type: "Passwords", desc: "Shared secrets used to authenticate." },
    { type: "Tokens", desc: "Session or API tokens used in place of passwords." },
    { type: "Keys", desc: "SSH or private keys for secure access." },
    { type: "Cookies", desc: "Browser sessions that can grant access." },
    { type: "Hashes", desc: "Hashed passwords that can sometimes be abused." },
  ];
  const accountTypes = [
    { type: "Local user", impact: "Limited to one device unless reused elsewhere." },
    { type: "Domain user", impact: "Can access multiple systems and services." },
    { type: "Service account", impact: "Often has broad, persistent access." },
    { type: "Admin account", impact: "High impact; can change systems or policies." },
    { type: "Cloud account", impact: "May access SaaS, mailboxes, or cloud resources." },
  ];
  const exampleFlow = [
    "User receives a fake login email and enters credentials.",
    "Attacker logs in from a new location using the stolen password.",
    "MFA blocks the login or the attacker tries another account.",
    "Security team sees unusual login alerts and investigates.",
    "Password reset and MFA enforcement stop further access.",
  ];

  const methods = [
    {
      title: "Phishing and Social Engineering",
      desc: "Attackers trick users into typing credentials into fake pages or prompts.",
      signals: "Unusual login locations, multiple failed attempts, new device logins.",
      prevention: "MFA, phishing training, and domain protections.",
    },
    {
      title: "Browser and Password Manager Abuse",
      desc: "Attackers attempt to access saved passwords or cookies.",
      signals: "Unexpected browser data access or profile copying.",
      prevention: "Restrict profile access, use OS account separation, MFA.",
    },
    {
      title: "Credential Dumping (High Level)",
      desc: "Attackers try to access credentials stored in memory or system stores.",
      signals: "Suspicious process access to LSASS or vault components.",
      prevention: "Credential Guard, LSASS protection, least privilege.",
    },
    {
      title: "Keylogging and Input Capture",
      desc: "Attempts to capture what a user types at the keyboard.",
      signals: "Unexpected keyboard hooks or unknown monitoring software.",
      prevention: "Endpoint protection, allowlisting, and user awareness.",
    },
    {
      title: "Token and Ticket Theft",
      desc: "Stealing session tokens or Kerberos tickets for reuse.",
      signals: "Unusual ticket usage or logons without interactive sessions.",
      prevention: "Short session lifetimes, monitoring, and segmentation.",
    },
    {
      title: "Secrets in Files",
      desc: "Credentials stored in config files, scripts, or notes.",
      signals: "Sensitive strings in repositories or user directories.",
      prevention: "Secret scanning, vaulting, and rotation.",
    },
    {
      title: "Legacy Protocol Abuse",
      desc: "Older protocols that do not enforce MFA or modern protections.",
      signals: "Logins from legacy auth or basic auth endpoints.",
      prevention: "Disable legacy protocols and enforce modern auth.",
    },
    {
      title: "Password Spraying (High Level)",
      desc: "Trying a few common passwords across many accounts.",
      signals: "Many accounts with a few failed attempts each.",
      prevention: "MFA, lockout policies, and monitoring.",
    },
  ];

  const storageTable = [
    {
      location: "Windows Credential Manager",
      risk: "Saved passwords can be abused if access controls are weak.",
      safeCheck: "cmdkey /list (read-only list of stored entries).",
    },
    {
      location: "LSASS memory",
      risk: "Credentials may be present in memory on some systems.",
      safeCheck: "Verify Credential Guard and LSA protection settings.",
    },
    {
      location: "Browser profiles",
      risk: "Saved passwords or session cookies stored in user profiles.",
      safeCheck: "Review profile permissions and access controls.",
    },
    {
      location: "Local files (.env, configs)",
      risk: "Secrets stored in plaintext configuration files.",
      safeCheck: "Use secret scanning in repos and user folders.",
    },
    {
      location: "SSH keys",
      risk: "Private keys stored without strong passphrases.",
      safeCheck: "Check key permissions and passphrase usage.",
    },
    {
      location: "CI/CD secrets",
      risk: "Build pipelines storing tokens with broad access.",
      safeCheck: "Review secret scopes and rotation schedules.",
    },
    {
      location: "Cloud access keys",
      risk: "Keys stored in local files or terminals.",
      safeCheck: "Check key age and least privilege policy.",
    },
  ];

  const signals = [
    "Many failed logins followed by a successful login.",
    "Credential access tools launched from unusual paths.",
    "Office or browser spawning command shells.",
    "Access to sensitive system processes by non-admin users.",
    "New logins from previously unseen devices or locations.",
  ];
  const behaviorIndicators = [
    "Multiple authentication attempts across many accounts.",
    "Unusual access to browser or vault data by non-browser processes.",
    "Repeated access to sensitive files by scripts or automation.",
    "High-volume access to credential stores in a short time window.",
  ];
  const redFlags = [
    "Password resets requested outside normal helpdesk flow.",
    "Multiple accounts locked out from a single IP.",
    "Tokens used after user sign-out or device wipe.",
    "Unusual authentication from legacy protocols.",
    "Credential access attempts on service accounts.",
  ];

  const telemetrySources = [
    "Process creation logs (with command-line arguments).",
    "Authentication logs and failed login records.",
    "Browser or application access logs.",
    "EDR alerts for credential access or dumping behavior.",
    "Secret scanning results and repository audit logs.",
  ];
  const detectionMatrix = [
    {
      stage: "Initial lure",
      signal: "User clicks a link from an unusual sender.",
      evidence: "Email logs and URL reputation.",
    },
    {
      stage: "Login attempt",
      signal: "New device or location sign-in.",
      evidence: "IdP sign-in logs and MFA prompts.",
    },
    {
      stage: "Credential access",
      signal: "Access to browser profiles or vault APIs.",
      evidence: "Process logs and EDR alerts.",
    },
    {
      stage: "Reuse",
      signal: "Same credentials used across services.",
      evidence: "Auth logs from multiple systems.",
    },
  ];
  const platformLogs = [
    { platform: "Windows", logs: "Security log, Defender/EDR, Sysmon if enabled." },
    { platform: "Linux", logs: "Auth logs, sudo logs, auditd if enabled." },
    { platform: "macOS", logs: "Unified logs, loginwindow, EDR logs." },
    { platform: "Cloud/SaaS", logs: "IdP logs, sign-in logs, audit logs." },
  ];
  const evidenceChecklist = [
    "User account and source IP",
    "Timestamp and device name",
    "Authentication method (password, MFA, token)",
    "Process tree for any local alerts",
    "Related alert IDs or EDR case links",
  ];

  const safeChecks = `# Windows: list stored credentials (read-only)
cmdkey /list

# Windows: check Credential Guard and LSA protections (read-only)
Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" | Select-Object RunAsPPL, LsaCfgFlags

# Windows: list local users (read-only)
Get-LocalUser | Select-Object Name, Enabled

# Linux: check permissions on /etc/shadow (read-only)
ls -l /etc/shadow

# macOS: list available keychains (read-only)
security list-keychains`;

  const beginnerLabSteps = [
    "Use a lab VM or test system you own.",
    "Create a fake secrets file in a lab folder (not real credentials).",
    "Run a simple search to find the fake secret.",
    "Document where it was found and how you would fix it.",
    "Enable MFA on a test account and note the difference in login flow.",
  ];
  const responseSteps = [
    "Reset impacted credentials and revoke active sessions.",
    "Check for lateral movement or reused passwords.",
    "Review MFA settings and enforce where missing.",
    "Communicate to affected users with clear guidance.",
    "Document the incident and update training material.",
  ];
  const preventionChecklist = [
    "Enable MFA everywhere possible.",
    "Use password managers and strong unique passwords.",
    "Harden browser profiles and protect stored credentials.",
    "Scan repos and endpoints for secrets regularly.",
    "Monitor for new devices and impossible travel logins.",
  ];
  const policyIdeas = [
    "Disable legacy authentication where possible.",
    "Require phishing-resistant MFA for admins.",
    "Rotate service account secrets on a schedule.",
    "Block password reuse with policy enforcement.",
    "Require approvals for new OAuth applications.",
  ];
  const safeBoundaries = [
    "Never handle real passwords in a lab exercise.",
    "Use fake secrets and disposable test accounts only.",
    "Avoid collecting sensitive user data during training.",
    "Get written approval before any testing outside a lab.",
  ];

  return (
    <LearnPageLayout pageTitle="Credential Harvesting" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: themeColors.bgDark, py: 4 }}>
      <Container maxWidth="xl">
        <Grid container spacing={3}>
          {/* Sidebar Navigation */}
          {!isMobile && (
            <Grid item md={2.5} sx={{ display: { xs: "none", md: "block" } }}>
              <Box sx={{ position: "sticky", top: 80 }}>
                <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden" }}>
                  {sidebarNav}
                </Paper>
              </Box>
            </Grid>
          )}

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

            {/* Introduction Section */}
            <Box id="intro" sx={{ scrollMarginTop: 80 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <VpnKeyIcon sx={{ fontSize: 42, color: themeColors.primary }} />
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
                  Credential Harvesting
                </Typography>
              </Box>
              <Typography variant="h6" sx={{ color: "grey.400", mb: 2 }}>
                Credential harvesting is the process of collecting usernames, passwords, or tokens so an attacker can log in.
              </Typography>
              <Paper elevation={0} sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2, border: `1px solid ${themeColors.border}` }}>
                <Typography variant="body1" sx={{ color: "grey.300", mb: 1 }}>
                  In simple terms, attackers want the same things you use to log in. They might trick people with fake
                  login pages, look for passwords saved in files, or abuse tools that access stored credentials. This page
                  focuses on the basics, the most common risks, and safe checks you can run in a lab.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  Credential harvesting is broader than just passwords. It includes API keys, session cookies, OAuth
                  tokens, and any secret that can prove identity. The techniques range from social engineering to
                  misconfigured storage to careless sharing in code or documentation.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  Think of credentials like keys. If someone copies the key, they can open the door without breaking it.
                  Learning where those keys are stored and how they are abused helps you protect accounts early.
                </Typography>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1, mt: 2 }}>
                  Defensive Focus
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                  Defenders care about reducing exposure, limiting credential reuse, and spotting abnormal access paths.
                  This page frames the topic from a protection and detection lens so teams can act before harvested
                  credentials lead to broader compromise.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400" }}>
                  Everything here is designed for beginners and uses read-only commands. The goal is to understand where
                  credentials live, how they are abused, and how to detect and prevent it.
                </Typography>
              </Paper>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip icon={<SecurityIcon />} label="Credentials" size="small" />
                <Chip icon={<SearchIcon />} label="Detection" size="small" />
                <Chip icon={<ShieldIcon />} label="Prevention" size="small" />
                <Chip icon={<WarningIcon />} label="Risk Areas" size="small" />
              </Box>
            </Box>

            {/* Overview Section */}
            <Box id="overview" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <SecurityIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Overview
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  How to Use This Section
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Use the overview to build a shared vocabulary and a clear mental model. Each block below adds context
                  for the part of the lifecycle it describes, so you can map real-world alerts and incidents to the
                  right prevention or detection control.
                </Typography>

                <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                    Learning Objectives
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    These objectives emphasize recognition and defensive response. By the end, you should be able to
                    explain where credentials tend to leak, describe common warning signals, and outline safe mitigation
                    steps without relying on offensive techniques.
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

                <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                    Beginner Path
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Follow this path to build intuition before diving into advanced details. Start with what
                    credentials are, where they live, and how normal access looks so you can quickly spot unusual
                    behavior later.
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

                <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                    Why This Is Hard
                  </Typography>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    Credential theft blends into everyday activity. Legitimate logins look similar to malicious ones,
                    and credentials can leak from many places at once, from browser stores to cloud tokens to exposed
                    files in repositories.
                  </Typography>
                  <List dense>
                    {whyHard.map((item) => (
                      <ListItem key={item}>
                        <ListItemIcon>
                          <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  What This Is Not
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  This page intentionally avoids step-by-step harvesting instructions or exploit guidance. It is
                  designed for awareness, defense, and safe lab learning only.
                </Typography>
                <List dense>
                  {whatItIsNot.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Quick Glossary
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Terminology in credential security can be confusing. These short definitions help standardize
                  language across teams so tickets and reports stay clear.
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

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Who Uses This Knowledge
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Credential risks cut across roles. Developers need to avoid hard-coded secrets, IT needs to manage
                  identity systems, and security teams need to detect suspicious access.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Role</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Focus</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {roles.map((item) => (
                        <TableRow key={item.role}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.role}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.focus}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Credential Types
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Different credential types carry different risks. Some are long-lived and reused, while others are
                  short-lived tokens that can still cause major damage if stolen within their validity window.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {credentialTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: "#0c0f1c", borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a855f7", mb: 1 }}>
                  Where Credentials Come From
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Most leaks are accidental rather than deliberate. Shared documents, misconfigured cloud storage,
                  and leftover test files are common sources that are easy to overlook.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Source</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Description</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {credentialSources.map((item) => (
                        <TableRow key={item.source}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.source}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.desc}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Account Types and Impact
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  The same credential leak can have very different consequences depending on the account type. Service
                  accounts and admin accounts usually have the widest blast radius.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Account Type</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Why it matters</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {accountTypes.map((item) => (
                        <TableRow key={item.type}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.type}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.impact}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Common Misconceptions
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Misconceptions often lead to weak controls or false confidence. Use these quick myth versus reality
                  notes to calibrate expectations across teams.
                </Typography>
                <Grid container spacing={2}>
                  {misconceptions.map((item) => (
                    <Grid item xs={12} md={4} key={item.myth}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: "#0b1020",
                          borderRadius: 2,
                          border: `1px solid ${alpha(themeColors.primary, 0.3)}`,
                          height: "100%",
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ color: themeColors.primary, mb: 1 }}>
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

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Example Flow (Simple)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  This high-level flow helps you understand where detection points live. The intent is to connect
                  a suspicious event to the phase where a control or response action is most effective.
                </Typography>
                <List dense>
                  {exampleFlow.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
              </Paper>
            </Box>

            {/* Methods Section */}
            <Box id="methods" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <WarningIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Methods (High Level)
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  Understanding Method Themes
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Credential harvesting methods generally fall into a few broad themes: tricking users, discovering
                  stored secrets, or intercepting authentication material in transit. Knowing the theme helps you pick
                  the right detection and prevention control.
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  The entries below describe each method at a safe, conceptual level. Focus on the signals and the
                  prevention notes to understand how defenders can break the chain early.
                </Typography>

              <Grid container spacing={2}>
                {methods.map((item) => (
                  <Grid item xs={12} md={6} key={item.title}>
                    <Paper
                      sx={{
                        p: 2,
                        bgcolor: themeColors.bgNested,
                        borderRadius: 2,
                        border: `1px solid ${alpha(themeColors.primary, 0.2)}`,
                        height: "100%",
                      }}
                    >
                      <Typography variant="subtitle1" sx={{ color: themeColors.text, fontWeight: 600 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.400", mb: 1 }}>
                        {item.desc}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#a5b4fc", display: "block" }}>
                        Signals: {item.signals}
                      </Typography>
                      <Typography variant="caption" sx={{ color: themeColors.textMuted, display: "block" }}>
                        Prevention: {item.prevention}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
              </Paper>
            </Box>

            {/* Storage & Risks Section */}
            <Box id="storage-risks" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <StorageIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Storage and Risks
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  Where Secrets Tend to Linger
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Credentials persist in more places than most teams expect. They can remain in browser stores, config
                  files, environment variables, or automation scripts long after the original need has passed. This
                  section highlights common locations and the risks tied to each.
                </Typography>

              <TableContainer sx={{ mb: 3 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: themeColors.primary }}>Location</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Risk</TableCell>
                      <TableCell sx={{ color: themeColors.primary }}>Safe Check</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {storageTable.map((item) => (
                      <TableRow key={item.location}>
                        <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.location}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.risk}</TableCell>
                        <TableCell sx={{ color: "grey.400" }}>{item.safeCheck}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                Safe Verification
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                Use the checks below only in controlled labs or approved environments. The intent is to confirm where
                credentials could be stored, not to extract or misuse sensitive data.
              </Typography>
              <Accordion sx={{ bgcolor: themeColors.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Safe Read-only Checks</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock code={safeChecks} language="powershell" />
                </AccordionDetails>
              </Accordion>
              </Paper>
            </Box>

            {/* Detection Section */}
            <Box id="detection" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <SearchIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Detection
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  Detection Strategy
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Credential harvesting detection is strongest when identity, endpoint, and network telemetry are
                  correlated. Single events can look benign, but patterns across systems often reveal misuse.
                </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Detection Signals
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Signals are early clues that something is wrong. Treat them as prompts to investigate rather than
                  definitive proof of compromise.
                </Typography>
                <List dense>
                  {signals.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Red Flags for Investigations
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Red flags are higher-confidence indicators that access may be compromised. They often combine unusual
                  authentication behavior with evidence of new tools, new devices, or unexpected data access.
                </Typography>
                <List dense>
                  {redFlags.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Behavior Indicators
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Behavior indicators often show up as changes in cadence or scope rather than a single alert. Look for
                  an account that suddenly touches many systems or accesses data it never used before.
                </Typography>
                <List dense>
                  {behaviorIndicators.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Telemetry Sources to Check
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Strong telemetry includes who, what, where, and when. Prioritize sources that tie actions to users
                  and devices so you can build a reliable timeline.
                </Typography>
                <List dense>
                  {telemetrySources.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="success" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Detection Matrix (Simple)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  The matrix links stages to evidence so you can track a case from initial exposure to confirmed misuse.
                  It also helps identify which parts of the chain you cannot yet observe.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Stage</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Signal</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Evidence</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {detectionMatrix.map((item) => (
                        <TableRow key={item.stage}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.stage}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.signal}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.evidence}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Platform Log Pointers
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Logs vary by platform and identity provider. Use these pointers as a starting point, then align them
                  with the exact log names and retention settings in your environment.
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: "#a5b4fc" }}>Platform</TableCell>
                        <TableCell sx={{ color: "#a5b4fc" }}>Logs to review</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {platformLogs.map((item) => (
                        <TableRow key={item.platform}>
                          <TableCell sx={{ color: "grey.200", fontWeight: 600 }}>{item.platform}</TableCell>
                          <TableCell sx={{ color: "grey.400" }}>{item.logs}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Evidence Checklist
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Evidence collection should preserve the original timeline and context. Keep it read-only, and record
                  hashes or timestamps so findings can be validated later.
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

            {/* Prevention Section */}
            <Box id="prevention" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <ShieldIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Prevention and Response
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  Layered Defense
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  Effective prevention combines identity controls, endpoint hardening, and continuous monitoring.
                  No single control stops every leak, but layered defenses reduce both likelihood and impact.
                </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Prevention Basics
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  These basics are high-impact and broadly applicable. Start here before implementing specialized
                  tooling or advanced identity controls.
                </Typography>
                <List dense>
                  {[
                    "Enable MFA for all critical systems.",
                    "Limit local admin privileges and rotate passwords.",
                    "Use password managers instead of browser auto-fill where possible.",
                    "Scan repositories and endpoints for secrets.",
                    "Harden LSASS with Credential Guard and RunAsPPL.",
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

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Prevention Checklist
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  The checklist is designed for repeatable hygiene. Use it during onboarding, audits, and incident
                  response reviews to ensure coverage stays consistent.
                </Typography>
                <List dense>
                  {preventionChecklist.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Policy and Control Ideas
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Policies make expectations clear and enforceable. When policies align with technical controls, teams
                  can prevent risky behavior without relying on manual review.
                </Typography>
                <List dense>
                  {policyIdeas.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
              <Paper sx={{ p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: "#a5b4fc", mb: 1 }}>
                  Beginner Triage Steps
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Triage should be calm and methodical. The goal is to confirm impact, contain risk, and communicate
                  clearly while preserving evidence.
                </Typography>
                <List dense>
                  {[
                    "Verify the alert details (user, host, and process).",
                    "Check if MFA was bypassed or not enabled.",
                    "Search for other hosts with the same indicator.",
                    "Reset impacted credentials and rotate tokens.",
                    "Escalate to incident response if multiple systems are affected.",
                  ].map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ mt: 3, p: 2.5, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Response Actions (Safe)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  These actions prioritize safety and accountability. Record what you change, ensure approvals are in
                  place, and coordinate with identity owners and platform teams.
                </Typography>
                <List dense>
                  {responseSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
              </Paper>
            </Box>

            {/* Beginner Lab Section */}
            <Box id="beginner-lab" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper elevation={0} sx={{ bgcolor: themeColors.bgCard, borderRadius: 3, border: `1px solid ${themeColors.border}`, overflow: "hidden", p: 3 }}>
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <ScienceIcon sx={{ color: themeColors.primary }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${themeColors.primary} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Beginner Lab
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <Typography variant="subtitle1" sx={{ color: themeColors.primary, fontWeight: 600, mb: 1 }}>
                  Lab Goals and Safety
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                  The lab focuses on observation and safe verification. You will practice recognizing where secrets
                  can appear and how to document findings without interacting with real user credentials.
                </Typography>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Beginner Lab Walkthrough (Safe)
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Use the walkthrough to build a repeatable, low-risk routine. The aim is to understand what normal
                  storage looks like and how to report exposures clearly.
                </Typography>
                <List dense>
                  {beginnerLabSteps.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="info" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Paper sx={{ p: 2.5, mb: 3, bgcolor: themeColors.bgNested, borderRadius: 2 }}>
                <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1 }}>
                  Safe Boundaries
                </Typography>
                <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                  Boundaries are essential. Keep the lab isolated, use fictional data, and stop immediately if any
                  action could touch production systems or real accounts.
                </Typography>
                <List dense>
                  {safeBoundaries.map((item) => (
                    <ListItem key={item}>
                      <ListItemIcon>
                        <CheckCircleIcon color="warning" fontSize="small" />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: "grey.300" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion sx={{ bgcolor: themeColors.bgNested }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="h6">Fake Secret Search Example</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" sx={{ color: "grey.400", mb: 2 }}>
                    This example creates a fake secret for practice. It demonstrates safe search techniques without
                    touching any real credentials or sensitive data.
                  </Typography>
                  <CodeBlock
                    language="powershell"
                    code={`# Create a safe lab file with a fake secret
New-Item -ItemType Directory -Force -Path C:\\LabSecrets
"API_KEY=FAKE-12345" | Out-File C:\\LabSecrets\\sample.env

# Search for the fake secret (read-only)
Select-String -Path C:\\LabSecrets\\* -Pattern "API_KEY"

# Clean up
Remove-Item -Recurse -Force C:\\LabSecrets`}
                  />
                </AccordionDetails>
              </Accordion>
              </Paper>
            </Box>

            {/* Quiz Section */}
            <Box id="quiz-section" sx={{ mt: 4, scrollMarginTop: 80 }}>
              <Paper
                elevation={0}
                sx={{
                  bgcolor: themeColors.bgCard,
                  borderRadius: 3,
                  border: `1px solid ${alpha(QUIZ_ACCENT_COLOR, 0.2)}`,
                  overflow: "hidden",
                  p: 3,
                }}
              >
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                    <QuizIcon sx={{ color: QUIZ_ACCENT_COLOR }} />
                    <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${QUIZ_ACCENT_COLOR} 0%, ${themeColors.primaryLight} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                      Knowledge Check
                    </Typography>
                  </Box>
                  <Divider sx={{ mt: 2, borderColor: themeColors.border }} />
                </Box>
                <QuizSection
                  questions={quizQuestions}
                  accentColor={QUIZ_ACCENT_COLOR}
                  title="Credential Harvesting Knowledge Check"
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
                sx={{ borderColor: themeColors.primary, color: themeColors.primary }}
              >
                Back to Learning Hub
              </Button>
            </Box>
            </Grid>
          </Grid>
        </Container>

        {/* Mobile navigation drawer */}
        <Drawer
          anchor="left"
          open={navDrawerOpen}
          onClose={() => setNavDrawerOpen(false)}
          sx={{ display: { xs: "block", md: "none" }, "& .MuiDrawer-paper": { width: 280, bgcolor: themeColors.bgCard, borderRight: `1px solid ${themeColors.border}` } }}
        >
          <Box sx={{ p: 2 }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: themeColors.primary }}>
                Navigation
              </Typography>
              <IconButton onClick={() => setNavDrawerOpen(false)} sx={{ color: themeColors.textMuted }}>
                <CloseIcon />
              </IconButton>
            </Box>
            {sidebarNav}
          </Box>
        </Drawer>

        {/* Mobile FABs */}
        <Box sx={{ display: { xs: "flex", md: "none" }, position: "fixed", bottom: 16, right: 16, flexDirection: "column", gap: 1, zIndex: 1000 }}>
          <Fab size="small" onClick={() => setNavDrawerOpen(true)} sx={{ bgcolor: themeColors.primary, color: "#fff", "&:hover": { bgcolor: themeColors.primaryLight } }}>
            <ListAltIcon />
          </Fab>
          <Fab size="small" onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })} sx={{ bgcolor: themeColors.bgCard, color: themeColors.primary, border: `1px solid ${themeColors.border}`, "&:hover": { bgcolor: themeColors.bgNested } }}>
            <KeyboardArrowUpIcon />
          </Fab>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default CredentialHarvestingPage;
