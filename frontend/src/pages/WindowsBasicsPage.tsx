import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import {
  Box,
  Button,
  Container,
  Typography,
  Paper,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import FolderIcon from "@mui/icons-material/Folder";
import SettingsIcon from "@mui/icons-material/Settings";
import PersonIcon from "@mui/icons-material/Person";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import SecurityIcon from "@mui/icons-material/Security";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SchoolIcon from "@mui/icons-material/School";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import HistoryIcon from "@mui/icons-material/History";
import AdminPanelSettingsIcon from "@mui/icons-material/AdminPanelSettings";
import SpeedIcon from "@mui/icons-material/Speed";
import BugReportIcon from "@mui/icons-material/BugReport";
import KeyIcon from "@mui/icons-material/Key";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LayersIcon from "@mui/icons-material/Layers";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import ShieldIcon from "@mui/icons-material/Shield";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import PolicyIcon from "@mui/icons-material/Policy";
import DnsIcon from "@mui/icons-material/Dns";
import RouterIcon from "@mui/icons-material/Router";
import GppGoodIcon from "@mui/icons-material/GppGood";
import FindInPageIcon from "@mui/icons-material/FindInPage";
import LockIcon from "@mui/icons-material/Lock";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import UpdateIcon from "@mui/icons-material/Update";
import DataObjectIcon from "@mui/icons-material/DataObject";

// Core Windows concepts
const windowsConcepts = [
  {
    title: "File System (NTFS)",
    icon: <FolderIcon />,
    color: "#f59e0b",
    description: "Windows uses NTFS (New Technology File System) as its primary file system for modern Windows versions.",
    keyPoints: [
      "Drive letters (C:, D:) vs Unix mount points",
      "Backslash (\\) as path separator",
      "Case-insensitive but case-preserving file names",
      "File permissions via Access Control Lists (ACLs)",
      "Alternate Data Streams (ADS) - hidden data storage",
      "File attributes: Hidden, System, Read-only, Archive",
      "Master File Table (MFT) stores file metadata",
      "Supports journaling for crash recovery",
    ],
    securityNote: "NTFS permissions and ACLs are critical for securing Windows systems. ADS can hide malware.",
    details: [
      "Maximum file size: 16 EB (theoretical), 256 TB (practical)",
      "Maximum volume size: 256 TB",
      "Supports compression, encryption (EFS), and quotas",
      "File names can be up to 255 characters",
    ],
  },
  {
    title: "Windows Registry",
    icon: <StorageIcon />,
    color: "#8b5cf6",
    description: "The Registry is a hierarchical database storing system configuration, application settings, and user preferences.",
    keyPoints: [
      "HKEY_LOCAL_MACHINE (HKLM) - System-wide settings",
      "HKEY_CURRENT_USER (HKCU) - User-specific settings",
      "HKEY_CLASSES_ROOT (HKCR) - File associations",
      "HKEY_USERS (HKU) - All user profiles",
      "HKEY_CURRENT_CONFIG (HKCC) - Hardware profile",
      "Registry keys (folders), values (name-data pairs)",
      "Data types: REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ",
      "regedit.exe and reg.exe for viewing/editing",
    ],
    securityNote: "Malware persistence mechanisms frequently abuse registry autorun keys like Run and RunOnce.",
    details: [
      "Physical files: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT",
      "Located in C:\\Windows\\System32\\config",
      "User hives in C:\\Users\\<user>\\NTUSER.DAT",
      "Registry virtualization for legacy app compatibility",
    ],
  },
  {
    title: "Windows Services",
    icon: <SettingsIcon />,
    color: "#10b981",
    description: "Services are long-running background processes that provide core OS functionality and application features.",
    keyPoints: [
      "services.msc - Service management console",
      "Service accounts: LocalSystem, LocalService, NetworkService",
      "Startup types: Automatic, Automatic (Delayed), Manual, Disabled",
      "sc.exe command for service control from CLI",
      "Service dependencies and load ordering",
      "Recovery options: Restart, Run Program, Reboot",
      "Service isolation and privileges",
      "Can be managed via PowerShell Get-Service/Set-Service",
    ],
    securityNote: "Misconfigured service permissions can lead to privilege escalation. Services running as SYSTEM are high-value targets.",
    details: [
      "Services run in Session 0, isolated from user sessions",
      "Interactive services are deprecated (security risk)",
      "Each service has an associated registry entry",
      "Service Control Manager (SCM) manages service lifecycle",
    ],
  },
  {
    title: "Users & Permissions",
    icon: <PersonIcon />,
    color: "#3b82f6",
    description: "Windows implements a robust user account and security permission system based on SIDs and ACLs.",
    keyPoints: [
      "Built-in accounts: Administrator, SYSTEM, Guest, DefaultAccount",
      "User groups: Administrators, Users, Power Users, Backup Operators",
      "User Account Control (UAC) - elevation prompts",
      "Security Identifiers (SIDs) uniquely identify principals",
      "Access tokens contain user's security context",
      "Privileges: SeDebugPrivilege, SeBackupPrivilege, etc.",
      "Local vs Domain (Active Directory) accounts",
      "Managed Service Accounts (MSA) and gMSA",
    ],
    securityNote: "Principle of least privilege should guide user permission assignments. Avoid using admin accounts for daily tasks.",
    details: [
      "SAM database stores local account info",
      "Password hashes: NTLM (MD4-based)",
      "Credential Guard protects hashes on modern systems",
      "LAPS for local admin password management",
    ],
  },
  {
    title: "Command Line Interfaces",
    icon: <TerminalIcon />,
    color: "#ef4444",
    description: "Windows provides multiple command-line environments: CMD, PowerShell, and Windows Terminal.",
    keyPoints: [
      "CMD.exe - Traditional command prompt (DOS heritage)",
      "PowerShell - Modern object-oriented shell",
      "Windows Terminal - New unified terminal app",
      "Environment variables: %PATH%, %USERPROFILE%, %TEMP%",
      "Running as Administrator for elevated operations",
      "Batch scripts (.bat, .cmd) for CMD automation",
      "PowerShell scripts (.ps1) with execution policies",
      "WSL (Windows Subsystem for Linux) for Linux tools",
    ],
    securityNote: "PowerShell is powerful for both administration and attacks. Constrained Language Mode and AMSI provide defense.",
    details: [
      "PowerShell execution policies: Restricted, RemoteSigned, Unrestricted",
      "PowerShell logging: Script Block, Module, Transcription",
      "cmd.exe location: C:\\Windows\\System32\\cmd.exe",
      "PowerShell location: C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
    ],
  },
  {
    title: "Processes & Memory",
    icon: <MemoryIcon />,
    color: "#06b6d4",
    description: "Understanding Windows process architecture is fundamental for troubleshooting and security analysis.",
    keyPoints: [
      "Processes contain one or more threads of execution",
      "Virtual memory: Each process has its own address space",
      "Kernel mode (Ring 0) vs User mode (Ring 3)",
      "Process ID (PID) and Parent Process ID (PPID)",
      "Task Manager (taskmgr.exe) for process viewing",
      "Process Monitor (procmon) for deep analysis",
      "Handle and DLL information per process",
      "Session ID associates processes with user sessions",
    ],
    securityNote: "Process injection and hollowing are common attack techniques. Monitor for suspicious parent-child relationships.",
    details: [
      "Critical processes: csrss.exe, lsass.exe, smss.exe, services.exe",
      "Session 0 isolation for services",
      "ASLR (Address Space Layout Randomization) for security",
      "DEP (Data Execution Prevention) prevents code execution in data regions",
    ],
  },
];

// Windows architecture components
const windowsArchitecture = [
  {
    layer: "User Mode",
    color: "#3b82f6",
    components: [
      { name: "Applications", description: "User-facing programs (notepad, browsers, etc.)" },
      { name: "Subsystem DLLs", description: "kernel32.dll, user32.dll, advapi32.dll" },
      { name: "NTDLL.DLL", description: "Interface to kernel, system call stubs" },
    ],
  },
  {
    layer: "Kernel Mode",
    color: "#ef4444",
    components: [
      { name: "Executive", description: "Memory manager, I/O manager, Security Reference Monitor" },
      { name: "Kernel", description: "Thread scheduling, interrupt handling, synchronization" },
      { name: "HAL", description: "Hardware Abstraction Layer - bridges kernel and hardware" },
      { name: "Drivers", description: "Device drivers for hardware interaction" },
    ],
  },
];

// Important directories
const importantDirectories = [
  { path: "C:\\Windows", description: "Core Windows OS files and system utilities", purpose: "System", notes: "Protected by Windows Resource Protection" },
  { path: "C:\\Windows\\System32", description: "64-bit system executables, DLLs, and drivers", purpose: "System", notes: "Contains cmd.exe, notepad.exe, etc." },
  { path: "C:\\Windows\\SysWOW64", description: "32-bit system files (WoW64 subsystem)", purpose: "System", notes: "For 32-bit app compatibility on 64-bit Windows" },
  { path: "C:\\Windows\\Temp", description: "System-wide temporary files", purpose: "Temporary", notes: "Cleanup scripts often target this location" },
  { path: "C:\\Windows\\Prefetch", description: "Application prefetch data for faster loading", purpose: "System", notes: "Useful for forensics - shows what ran" },
  { path: "C:\\Windows\\System32\\config", description: "Registry hive files (SAM, SYSTEM, SOFTWARE)", purpose: "System", notes: "Critical for forensics and attacks" },
  { path: "C:\\Windows\\System32\\drivers\\etc", description: "hosts file, services, protocol definitions", purpose: "System", notes: "hosts file can redirect domains" },
  { path: "C:\\Program Files", description: "64-bit application installations", purpose: "Applications", notes: "Requires admin to modify" },
  { path: "C:\\Program Files (x86)", description: "32-bit application installations", purpose: "Applications", notes: "WoW64 redirect for 32-bit apps" },
  { path: "C:\\ProgramData", description: "Machine-wide application data (shared)", purpose: "Applications", notes: "Hidden by default, apps store configs here" },
  { path: "C:\\Users", description: "User profile root folder", purpose: "User Data", notes: "Contains all user home directories" },
  { path: "C:\\Users\\<user>\\Desktop", description: "User's desktop files and shortcuts", purpose: "User Data", notes: "Common malware drop location" },
  { path: "C:\\Users\\<user>\\Documents", description: "User's documents folder", purpose: "User Data", notes: "Often targeted by ransomware" },
  { path: "C:\\Users\\<user>\\Downloads", description: "Default download location", purpose: "User Data", notes: "Primary malware entry point" },
  { path: "C:\\Users\\<user>\\AppData\\Local", description: "Local application data (not roamed)", purpose: "User Data", notes: "App caches and local settings" },
  { path: "C:\\Users\\<user>\\AppData\\Roaming", description: "Roaming application data (syncs with domain)", purpose: "User Data", notes: "Follows user in domain environments" },
  { path: "C:\\Users\\<user>\\AppData\\Local\\Temp", description: "User's temporary files", purpose: "Temporary", notes: "Common malware staging area" },
  { path: "C:\\Users\\Public", description: "Shared files accessible to all users", purpose: "User Data", notes: "Useful for data sharing between users" },
];

// Registry keys important for security
const registryKeys = [
  {
    hive: "HKLM",
    key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Programs that run at startup (all users)",
    securityRelevance: "HIGH",
    notes: "Common malware persistence location",
  },
  {
    hive: "HKCU",
    key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Programs that run at startup (current user)",
    securityRelevance: "HIGH",
    notes: "User-specific autorun, no admin needed",
  },
  {
    hive: "HKLM",
    key: "SYSTEM\\CurrentControlSet\\Services",
    description: "Windows services configuration",
    securityRelevance: "HIGH",
    notes: "Attackers create services for persistence",
  },
  {
    hive: "HKLM",
    key: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    description: "Winlogon settings and shell configuration",
    securityRelevance: "HIGH",
    notes: "Shell and Userinit values can be hijacked",
  },
  {
    hive: "HKLM",
    key: "SOFTWARE\\Classes\\*\\shell",
    description: "Context menu handlers for all file types",
    securityRelevance: "MEDIUM",
    notes: "Can add malicious right-click options",
  },
  {
    hive: "HKCU",
    key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    description: "Recent Run dialog commands",
    securityRelevance: "LOW",
    notes: "Forensics: shows what user ran",
  },
  {
    hive: "HKLM",
    key: "SAM\\SAM\\Domains\\Account\\Users",
    description: "Local user account information",
    securityRelevance: "CRITICAL",
    notes: "Contains password hashes (protected)",
  },
  {
    hive: "HKLM",
    key: "SECURITY\\Policy\\Secrets",
    description: "LSA secrets (cached credentials, service passwords)",
    securityRelevance: "CRITICAL",
    notes: "Target for credential dumping",
  },
];

// Essential commands - expanded
const essentialCommands = [
  { command: "dir", description: "List directory contents", example: "dir /a /s", category: "Navigation", flags: "/a (all), /s (recursive), /b (bare), /o (order)" },
  { command: "cd", description: "Change directory", example: "cd C:\\Users", category: "Navigation", flags: "/d (change drive too)" },
  { command: "type", description: "Display file contents", example: "type file.txt", category: "Files", flags: "Use with | more for paging" },
  { command: "copy / xcopy", description: "Copy files and directories", example: "xcopy /s /e source dest", category: "Files", flags: "/s (subdirs), /e (empty too), /h (hidden)" },
  { command: "move", description: "Move files or rename", example: "move file.txt newdir\\", category: "Files", flags: "/y (suppress prompt)" },
  { command: "del / erase", description: "Delete files", example: "del /f /q file.txt", category: "Files", flags: "/f (force), /q (quiet), /s (subdirs)" },
  { command: "mkdir / md", description: "Create directory", example: "mkdir newFolder", category: "Files", flags: "Creates parent dirs automatically" },
  { command: "rmdir / rd", description: "Remove directory", example: "rmdir /s /q folder", category: "Files", flags: "/s (recursive), /q (quiet)" },
  { command: "attrib", description: "View/change file attributes", example: "attrib +h file.txt", category: "Files", flags: "+/- r (read), h (hidden), s (system)" },
  { command: "icacls", description: "Display/modify ACLs", example: "icacls file.txt /grant Users:R", category: "Security", flags: "/grant, /deny, /remove, /reset" },
  { command: "tasklist", description: "List running processes", example: "tasklist /v /fi \"STATUS eq running\"", category: "Processes", flags: "/v (verbose), /fi (filter), /svc (services)" },
  { command: "taskkill", description: "Terminate processes", example: "taskkill /PID 1234 /F", category: "Processes", flags: "/PID (by ID), /IM (by name), /F (force)" },
  { command: "sc", description: "Service control", example: "sc query state= all", category: "Services", flags: "query, start, stop, config, create, delete" },
  { command: "net user", description: "Manage user accounts", example: "net user username /domain", category: "Users", flags: "/add, /delete, /domain" },
  { command: "net localgroup", description: "Manage local groups", example: "net localgroup Administrators", category: "Users", flags: "/add, /delete" },
  { command: "net share", description: "View/manage network shares", example: "net share", category: "Network", flags: "/delete, /grant" },
  { command: "netstat", description: "Network connections", example: "netstat -ano", category: "Network", flags: "-a (all), -n (numeric), -o (PID), -b (process)" },
  { command: "ipconfig", description: "Network configuration", example: "ipconfig /all", category: "Network", flags: "/all, /release, /renew, /flushdns" },
  { command: "ping", description: "Test connectivity", example: "ping -t google.com", category: "Network", flags: "-t (continuous), -n (count), -l (size)" },
  { command: "tracert", description: "Trace route to host", example: "tracert google.com", category: "Network", flags: "-d (no DNS), -h (max hops)" },
  { command: "nslookup", description: "DNS query tool", example: "nslookup domain.com 8.8.8.8", category: "Network", flags: "Interactive mode with 'server' and 'set type'" },
  { command: "arp", description: "View/modify ARP cache", example: "arp -a", category: "Network", flags: "-a (display), -d (delete), -s (static)" },
  { command: "route", description: "View/modify routing table", example: "route print", category: "Network", flags: "print, add, delete, change" },
  { command: "systeminfo", description: "Detailed system information", example: "systeminfo", category: "System", flags: "/s (remote), /u (user), /p (password)" },
  { command: "hostname", description: "Display computer name", example: "hostname", category: "System", flags: "No flags" },
  { command: "whoami", description: "Current user and privileges", example: "whoami /priv", category: "Security", flags: "/priv, /groups, /all" },
  { command: "gpresult", description: "Group policy results", example: "gpresult /r", category: "Security", flags: "/r (summary), /v (verbose), /z (super verbose)" },
  { command: "wmic", description: "WMI command line", example: "wmic process list brief", category: "System", flags: "process, service, os, useraccount, etc." },
  { command: "schtasks", description: "Scheduled tasks", example: "schtasks /query /fo LIST", category: "System", flags: "/create, /delete, /query, /run" },
  { command: "reg", description: "Registry CLI tool", example: "reg query HKLM\\SOFTWARE", category: "System", flags: "query, add, delete, export, import" },
];

// PowerShell equivalents - expanded
const powershellCommands = [
  { cmd: "dir", ps: "Get-ChildItem", alias: "gci, ls, dir", usage: "Get-ChildItem -Path C:\\ -Recurse -Force" },
  { cmd: "type", ps: "Get-Content", alias: "gc, cat, type", usage: "Get-Content file.txt -Tail 10" },
  { cmd: "copy", ps: "Copy-Item", alias: "cp, copy", usage: "Copy-Item -Path source -Destination dest -Recurse" },
  { cmd: "move", ps: "Move-Item", alias: "mv, move", usage: "Move-Item -Path file.txt -Destination newdir\\" },
  { cmd: "del", ps: "Remove-Item", alias: "rm, del", usage: "Remove-Item -Path file.txt -Force" },
  { cmd: "mkdir", ps: "New-Item -ItemType Directory", alias: "md, mkdir", usage: "New-Item -Path newdir -ItemType Directory" },
  { cmd: "tasklist", ps: "Get-Process", alias: "gps, ps", usage: "Get-Process | Where-Object {$_.CPU -gt 10}" },
  { cmd: "taskkill", ps: "Stop-Process", alias: "kill, spps", usage: "Stop-Process -Id 1234 -Force" },
  { cmd: "net user", ps: "Get-LocalUser", alias: "-", usage: "Get-LocalUser | Select-Object Name, Enabled" },
  { cmd: "net localgroup", ps: "Get-LocalGroupMember", alias: "-", usage: "Get-LocalGroupMember -Group 'Administrators'" },
  { cmd: "sc query", ps: "Get-Service", alias: "gsv", usage: "Get-Service | Where-Object {$_.Status -eq 'Running'}" },
  { cmd: "ipconfig", ps: "Get-NetIPConfiguration", alias: "-", usage: "Get-NetIPConfiguration | Select InterfaceAlias, IPv4Address" },
  { cmd: "netstat", ps: "Get-NetTCPConnection", alias: "-", usage: "Get-NetTCPConnection -State Established" },
  { cmd: "systeminfo", ps: "Get-ComputerInfo", alias: "-", usage: "Get-ComputerInfo | Select OsName, OsVersion" },
  { cmd: "reg query", ps: "Get-ItemProperty", alias: "-", usage: "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft'" },
  { cmd: "schtasks", ps: "Get-ScheduledTask", alias: "-", usage: "Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}" },
];

// Important Windows processes
const importantProcesses = [
  { process: "System", pid: "4", parent: "None", description: "Kernel and driver threads", notes: "Always PID 4, if not - suspicious" },
  { process: "smss.exe", pid: "Variable", parent: "System", description: "Session Manager", notes: "Should only be 1-2 instances" },
  { process: "csrss.exe", pid: "Variable", parent: "smss.exe", description: "Client Server Runtime", notes: "One per session (0 and 1+)" },
  { process: "wininit.exe", pid: "Variable", parent: "smss.exe", description: "Windows Initialization", notes: "Session 0 only" },
  { process: "winlogon.exe", pid: "Variable", parent: "smss.exe", description: "Logon handler", notes: "One per interactive session" },
  { process: "services.exe", pid: "Variable", parent: "wininit.exe", description: "Service Control Manager", notes: "Parent of all services" },
  { process: "lsass.exe", pid: "Variable", parent: "wininit.exe", description: "Local Security Authority", notes: "Handles authentication, credential storage" },
  { process: "svchost.exe", pid: "Variable", parent: "services.exe", description: "Service host process", notes: "Multiple instances, check -k parameter" },
  { process: "explorer.exe", pid: "Variable", parent: "userinit.exe", description: "Windows Shell/Desktop", notes: "Parent of user-launched programs" },
  { process: "RuntimeBroker.exe", pid: "Variable", parent: "svchost.exe", description: "UWP app permissions", notes: "Multiple instances OK" },
];

// Common Windows event IDs for security
const securityEventIds = [
  { eventId: "4624", description: "Successful logon", category: "Authentication", notes: "Check logon type (2=interactive, 3=network, 10=remote)" },
  { eventId: "4625", description: "Failed logon", category: "Authentication", notes: "Watch for brute force patterns" },
  { eventId: "4648", description: "Explicit credential logon", category: "Authentication", notes: "runas or network auth with different creds" },
  { eventId: "4672", description: "Special privileges assigned", category: "Privileges", notes: "Admin/sensitive logon detected" },
  { eventId: "4688", description: "Process creation", category: "Process", notes: "Requires audit policy, shows command line" },
  { eventId: "4689", description: "Process termination", category: "Process", notes: "Correlate with 4688" },
  { eventId: "4698", description: "Scheduled task created", category: "Persistence", notes: "Common persistence mechanism" },
  { eventId: "4720", description: "User account created", category: "Account", notes: "Attackers may create accounts" },
  { eventId: "4732", description: "User added to local group", category: "Account", notes: "Watch for Administrators group" },
  { eventId: "7045", description: "Service installed", category: "Persistence", notes: "New service = potential persistence" },
  { eventId: "1102", description: "Audit log cleared", category: "Defense Evasion", notes: "Very suspicious if unexpected" },
];

// Keyboard shortcuts
const keyboardShortcuts = [
  { shortcut: "Win + R", action: "Open Run dialog", category: "System" },
  { shortcut: "Win + E", action: "Open File Explorer", category: "Navigation" },
  { shortcut: "Win + X", action: "Power User menu (admin tools)", category: "System" },
  { shortcut: "Win + I", action: "Open Settings", category: "System" },
  { shortcut: "Ctrl + Shift + Esc", action: "Open Task Manager directly", category: "System" },
  { shortcut: "Win + Pause", action: "System Properties", category: "System" },
  { shortcut: "Win + L", action: "Lock workstation", category: "Security" },
  { shortcut: "Alt + F4", action: "Close current window", category: "Navigation" },
  { shortcut: "Ctrl + Shift + Enter", action: "Run as Administrator (from search)", category: "Security" },
  { shortcut: "Win + Tab", action: "Task View / Virtual Desktops", category: "Navigation" },
  { shortcut: "Win + D", action: "Show/Hide Desktop", category: "Navigation" },
  { shortcut: "Win + S", action: "Open Search", category: "System" },
  { shortcut: "Win + V", action: "Clipboard History", category: "System" },
  { shortcut: "Win + Shift + S", action: "Screenshot (Snip & Sketch)", category: "System" },
  { shortcut: "Ctrl + Alt + Del", action: "Security Options Screen", category: "Security" },
  { shortcut: "F2", action: "Rename selected item", category: "Navigation" },
];

// Windows versions for context
const windowsVersions = [
  { version: "Windows 11", release: "2021", kernel: "10.0.22000+", notes: "Latest version, TPM 2.0 required, new UI" },
  { version: "Windows 10", release: "2015", kernel: "10.0.10240+", notes: "Most common enterprise version" },
  { version: "Windows 8.1", release: "2013", kernel: "6.3", notes: "Extended support ended Jan 2023" },
  { version: "Windows 7", release: "2009", kernel: "6.1", notes: "End of life Jan 2020, still seen in legacy" },
  { version: "Windows Server 2022", release: "2021", kernel: "10.0.20348", notes: "Current server release" },
  { version: "Windows Server 2019", release: "2018", kernel: "10.0.17763", notes: "Common in enterprises" },
  { version: "Windows Server 2016", release: "2016", kernel: "10.0.14393", notes: "Widely deployed" },
];

// Windows boot process
const bootProcess = [
  { step: "1", name: "UEFI/BIOS", description: "Hardware initialization, POST, loads bootloader from EFI System Partition or MBR" },
  { step: "2", name: "Boot Manager", description: "bootmgfw.efi (UEFI) or bootmgr (BIOS) loads Windows Boot Configuration Data (BCD)" },
  { step: "3", name: "Windows Loader", description: "winload.efi/winload.exe loads kernel (ntoskrnl.exe), HAL, and boot drivers" },
  { step: "4", name: "Kernel Init", description: "ntoskrnl.exe initializes, loads SYSTEM registry hive, starts Session Manager (smss.exe)" },
  { step: "5", name: "Session Manager", description: "smss.exe creates environment variables, starts csrss.exe and winlogon.exe" },
  { step: "6", name: "Winlogon", description: "winlogon.exe handles logon, loads user profile, starts explorer.exe" },
];

// Common Windows tools
const windowsTools = [
  { tool: "Task Manager", command: "taskmgr.exe", description: "Process, performance, and service monitoring", category: "Built-in" },
  { tool: "Event Viewer", command: "eventvwr.msc", description: "Windows logs and event analysis", category: "Built-in" },
  { tool: "Registry Editor", command: "regedit.exe", description: "Edit Windows Registry", category: "Built-in" },
  { tool: "Services Console", command: "services.msc", description: "Manage Windows services", category: "Built-in" },
  { tool: "Computer Management", command: "compmgmt.msc", description: "Unified admin console", category: "Built-in" },
  { tool: "Device Manager", command: "devmgmt.msc", description: "Hardware and drivers", category: "Built-in" },
  { tool: "Disk Management", command: "diskmgmt.msc", description: "Partition and volume management", category: "Built-in" },
  { tool: "Group Policy Editor", command: "gpedit.msc", description: "Local policy configuration (Pro/Enterprise)", category: "Built-in" },
  { tool: "Process Explorer", command: "procexp.exe", description: "Advanced process management", category: "Sysinternals" },
  { tool: "Process Monitor", command: "procmon.exe", description: "Real-time file/registry/process monitoring", category: "Sysinternals" },
  { tool: "Autoruns", command: "autoruns.exe", description: "Shows all auto-start programs", category: "Sysinternals" },
  { tool: "TCPView", command: "tcpview.exe", description: "Active network connections", category: "Sysinternals" },
  { tool: "PsExec", command: "psexec.exe", description: "Remote command execution", category: "Sysinternals" },
  { tool: "Sigcheck", command: "sigcheck.exe", description: "Verify digital signatures", category: "Sysinternals" },
];

// Environment variables
const environmentVariables = [
  { variable: "%SYSTEMROOT%", example: "C:\\Windows", description: "Windows installation directory" },
  { variable: "%SYSTEMDRIVE%", example: "C:", description: "Drive containing Windows" },
  { variable: "%USERPROFILE%", example: "C:\\Users\\username", description: "Current user's profile folder" },
  { variable: "%APPDATA%", example: "C:\\Users\\username\\AppData\\Roaming", description: "Roaming application data" },
  { variable: "%LOCALAPPDATA%", example: "C:\\Users\\username\\AppData\\Local", description: "Local application data" },
  { variable: "%TEMP%", example: "C:\\Users\\username\\AppData\\Local\\Temp", description: "Temporary files location" },
  { variable: "%PATH%", example: "System path directories", description: "Executable search paths" },
  { variable: "%COMPUTERNAME%", example: "DESKTOP-ABC123", description: "Machine hostname" },
  { variable: "%USERNAME%", example: "john.doe", description: "Current logged-in user" },
  { variable: "%USERDOMAIN%", example: "CONTOSO", description: "User's domain name" },
  { variable: "%PROGRAMFILES%", example: "C:\\Program Files", description: "64-bit program installations" },
  { variable: "%PROGRAMFILES(X86)%", example: "C:\\Program Files (x86)", description: "32-bit program installations" },
  { variable: "%WINDIR%", example: "C:\\Windows", description: "Windows directory (alias for SYSTEMROOT)" },
  { variable: "%HOMEDRIVE%", example: "C:", description: "Drive letter of user's home" },
  { variable: "%HOMEPATH%", example: "\\Users\\username", description: "Path to user's home from drive root" },
  { variable: "%PUBLIC%", example: "C:\\Users\\Public", description: "Public user profile folder" },
  { variable: "%ALLUSERSPROFILE%", example: "C:\\ProgramData", description: "All users profile data" },
  { variable: "%LOGONSERVER%", example: "\\\\DC01", description: "Domain controller that authenticated user" },
];

// Windows Security Features
const windowsSecurityFeatures = [
  {
    name: "Windows Defender Antivirus",
    icon: <ShieldIcon />,
    color: "#10b981",
    description: "Built-in real-time malware protection",
    keyFeatures: [
      "Real-time protection against malware, viruses, and spyware",
      "Cloud-delivered protection for faster threat detection",
      "Automatic sample submission for new threats",
      "Behavior monitoring and suspicious activity blocking",
      "Network inspection for exploit-based attacks",
      "Controlled folder access (ransomware protection)",
      "Attack Surface Reduction (ASR) rules",
    ],
    commands: [
      { cmd: "Get-MpComputerStatus", desc: "Check Defender status" },
      { cmd: "Update-MpSignature", desc: "Update definitions" },
      { cmd: "Start-MpScan -ScanType QuickScan", desc: "Run quick scan" },
      { cmd: "Get-MpThreatDetection", desc: "View detected threats" },
    ],
  },
  {
    name: "Windows Firewall",
    icon: <GppGoodIcon />,
    color: "#3b82f6",
    description: "Host-based firewall for network traffic filtering",
    keyFeatures: [
      "Inbound and outbound traffic filtering",
      "Domain, Private, and Public profiles",
      "Application-specific rules",
      "Connection security rules (IPsec)",
      "Logging of blocked connections",
      "Integration with Windows Defender",
      "PowerShell and netsh management",
    ],
    commands: [
      { cmd: "Get-NetFirewallProfile", desc: "View firewall profiles" },
      { cmd: "Get-NetFirewallRule", desc: "List firewall rules" },
      { cmd: "netsh advfirewall show allprofiles", desc: "Show profile status" },
      { cmd: "New-NetFirewallRule", desc: "Create new rule" },
    ],
  },
  {
    name: "BitLocker Drive Encryption",
    icon: <LockIcon />,
    color: "#8b5cf6",
    description: "Full disk encryption for data protection",
    keyFeatures: [
      "Full volume encryption using AES-128 or AES-256",
      "TPM integration for secure key storage",
      "Pre-boot authentication options",
      "Recovery key for emergency access",
      "BitLocker To Go for removable drives",
      "Network unlock for enterprise deployments",
      "Used space only encryption option",
    ],
    commands: [
      { cmd: "manage-bde -status", desc: "Check encryption status" },
      { cmd: "Get-BitLockerVolume", desc: "View BitLocker volumes" },
      { cmd: "Enable-BitLocker", desc: "Enable encryption" },
      { cmd: "(Get-BitLockerVolume).KeyProtector", desc: "View recovery keys" },
    ],
  },
  {
    name: "Credential Guard",
    icon: <VpnKeyIcon />,
    color: "#ef4444",
    description: "Virtualization-based credential protection",
    keyFeatures: [
      "Isolates LSASS secrets using VBS",
      "Protects NTLM hashes and Kerberos tickets",
      "Prevents pass-the-hash and pass-the-ticket attacks",
      "Requires UEFI Secure Boot and TPM 2.0",
      "Hardware-based security isolation",
      "Integrated with Windows 10/11 Enterprise",
    ],
    commands: [
      { cmd: "Get-CimInstance -ClassName Win32_DeviceGuard", desc: "Check Device Guard status" },
      { cmd: "msinfo32.exe", desc: "System Information (shows VBS status)" },
    ],
  },
  {
    name: "User Account Control (UAC)",
    icon: <AdminPanelSettingsIcon />,
    color: "#f59e0b",
    description: "Elevation prompts for administrative actions",
    keyFeatures: [
      "Prompts for elevation when admin rights needed",
      "Standard user token for regular operations",
      "Admin Approval Mode for administrators",
      "Configurable notification levels",
      "Secure Desktop for elevation prompts",
      "File and registry virtualization for legacy apps",
    ],
    commands: [
      { cmd: "whoami /priv", desc: "Check current privileges" },
      { cmd: "Get-ExecutionPolicy", desc: "Check PS execution policy" },
      { cmd: "runas /user:Administrator cmd", desc: "Run as different user" },
    ],
  },
  {
    name: "Windows Defender SmartScreen",
    icon: <VerifiedUserIcon />,
    color: "#06b6d4",
    description: "Reputation-based protection against untrusted downloads",
    keyFeatures: [
      "Checks files against known malware database",
      "Blocks downloads from unknown sources",
      "Application reputation checking",
      "Microsoft Edge integration",
      "Phishing and malware site blocking",
      "Enterprise configurable via Group Policy",
    ],
    commands: [
      { cmd: "Get-MpPreference | Select SmartScreen*", desc: "Check SmartScreen settings" },
    ],
  },
];

// Group Policy Important Settings
const groupPolicySettings = [
  {
    category: "Password Policy",
    path: "Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy",
    settings: [
      { name: "Minimum password length", recommended: "14+ characters", risk: "Short passwords easily cracked" },
      { name: "Password complexity requirements", recommended: "Enabled", risk: "Simple passwords vulnerable" },
      { name: "Maximum password age", recommended: "90-365 days", risk: "Never-expiring passwords" },
      { name: "Password history", recommended: "24 passwords", risk: "Password reuse" },
    ],
  },
  {
    category: "Account Lockout Policy",
    path: "Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy",
    settings: [
      { name: "Account lockout threshold", recommended: "5-10 attempts", risk: "Unlimited attempts allow brute force" },
      { name: "Account lockout duration", recommended: "15-30 minutes", risk: "Too short allows rapid retries" },
      { name: "Reset lockout counter after", recommended: "15 minutes", risk: "Immediate reset enables attacks" },
    ],
  },
  {
    category: "Audit Policy",
    path: "Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration",
    settings: [
      { name: "Audit logon events", recommended: "Success, Failure", risk: "No visibility into auth attempts" },
      { name: "Audit process creation", recommended: "Success", risk: "Cannot track malware execution" },
      { name: "Audit privilege use", recommended: "Success, Failure", risk: "No admin activity tracking" },
      { name: "Audit object access", recommended: "Success, Failure", risk: "No file access auditing" },
    ],
  },
  {
    category: "User Rights Assignment",
    path: "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment",
    settings: [
      { name: "Debug programs (SeDebugPrivilege)", recommended: "Administrators only", risk: "Allows memory access to any process" },
      { name: "Act as part of OS", recommended: "No one", risk: "Highly privileged, rarely needed" },
      { name: "Load and unload device drivers", recommended: "Administrators only", risk: "Can load malicious drivers" },
      { name: "Take ownership of files", recommended: "Administrators only", risk: "Can access any file" },
    ],
  },
  {
    category: "Windows Defender Settings",
    path: "Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus",
    settings: [
      { name: "Turn off real-time protection", recommended: "Not Configured/Disabled", risk: "No malware protection" },
      { name: "Configure Attack Surface Reduction rules", recommended: "Enabled with rules", risk: "Missing exploit protection" },
      { name: "Cloud-based protection", recommended: "Enabled", risk: "Slower threat detection" },
    ],
  },
];

// Forensic Artifacts
const forensicArtifacts = [
  {
    category: "User Activity",
    color: "#3b82f6",
    artifacts: [
      { name: "NTUSER.DAT", location: "C:\\Users\\<user>\\NTUSER.DAT", description: "User registry hive - MRU lists, typed paths, user settings" },
      { name: "UsrClass.dat", location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", description: "ShellBags - folder access history" },
      { name: "Recent Items", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent", description: "Recently accessed files (LNK files)" },
      { name: "Jump Lists", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations", description: "Application-specific recent items" },
      { name: "Prefetch", location: "C:\\Windows\\Prefetch", description: "Application execution history (.pf files)" },
      { name: "BAM/DAM", location: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", description: "Background/Desktop Activity Moderator - execution times" },
    ],
  },
  {
    category: "Network Activity",
    color: "#10b981",
    artifacts: [
      { name: "SRUM Database", location: "C:\\Windows\\System32\\sru\\SRUDB.dat", description: "Network data usage by application" },
      { name: "Network Profiles", location: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList", description: "Connected networks history" },
      { name: "DNS Cache", location: "ipconfig /displaydns (memory)", description: "Recent DNS resolutions" },
      { name: "Firewall Logs", location: "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log", description: "Blocked connection attempts" },
    ],
  },
  {
    category: "File System",
    color: "#f59e0b",
    artifacts: [
      { name: "$MFT", location: "C:\\$MFT (hidden)", description: "Master File Table - all file metadata" },
      { name: "$UsnJrnl", location: "C:\\$Extend\\$UsnJrnl", description: "Change journal - file modifications" },
      { name: "$LogFile", location: "C:\\$LogFile", description: "NTFS transaction log" },
      { name: "Recycle Bin", location: "C:\\$Recycle.Bin\\<SID>", description: "Deleted files with original path info" },
      { name: "Thumbcache", location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer", description: "Thumbnail database - viewed images" },
    ],
  },
  {
    category: "System Logs",
    color: "#ef4444",
    artifacts: [
      { name: "Security.evtx", location: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", description: "Authentication and authorization events" },
      { name: "System.evtx", location: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx", description: "Driver and service events" },
      { name: "Application.evtx", location: "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx", description: "Application errors and info" },
      { name: "PowerShell Logs", location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx", description: "PowerShell execution history" },
      { name: "Sysmon Logs", location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx", description: "Detailed process and network monitoring (if installed)" },
    ],
  },
  {
    category: "Persistence Locations",
    color: "#8b5cf6",
    artifacts: [
      { name: "Run Keys", location: "HKLM/HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", description: "Startup programs" },
      { name: "Startup Folder", location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", description: "User startup items" },
      { name: "Scheduled Tasks", location: "C:\\Windows\\System32\\Tasks", description: "Task Scheduler XML files" },
      { name: "Services", location: "HKLM\\SYSTEM\\CurrentControlSet\\Services", description: "Windows services registry" },
      { name: "WMI Subscriptions", location: "WMI Repository", description: "WMI event subscriptions (advanced persistence)" },
    ],
  },
];

// Additional Security Event IDs
const additionalSecurityEvents = [
  { eventId: "4634", description: "Account logoff", category: "Authentication", notes: "Correlate with 4624 for session duration" },
  { eventId: "4647", description: "User-initiated logoff", category: "Authentication", notes: "User explicitly logged off" },
  { eventId: "4648", description: "Explicit credentials logon", category: "Authentication", notes: "Runas or network with different creds" },
  { eventId: "4656", description: "Handle to object requested", category: "Object Access", notes: "File/registry access attempt" },
  { eventId: "4663", description: "Attempt to access object", category: "Object Access", notes: "Actual access to file/registry" },
  { eventId: "4670", description: "Permissions on object changed", category: "Object Access", notes: "ACL modification" },
  { eventId: "4697", description: "Service installed", category: "Persistence", notes: "New service (need to enable auditing)" },
  { eventId: "4700", description: "Scheduled task enabled", category: "Persistence", notes: "Task Scheduler changes" },
  { eventId: "4701", description: "Scheduled task disabled", category: "Persistence", notes: "Possible defense evasion" },
  { eventId: "4702", description: "Scheduled task updated", category: "Persistence", notes: "Task modification" },
  { eventId: "4703", description: "User right adjusted", category: "Privileges", notes: "Token manipulation" },
  { eventId: "4719", description: "Audit policy changed", category: "Defense Evasion", notes: "Attacker may disable logging" },
  { eventId: "4724", description: "Password reset attempted", category: "Account", notes: "Admin reset user password" },
  { eventId: "4728", description: "Member added to global group", category: "Account", notes: "Domain group changes" },
  { eventId: "4756", description: "Member added to universal group", category: "Account", notes: "Universal group changes" },
  { eventId: "4768", description: "Kerberos TGT requested", category: "Kerberos", notes: "Initial authentication to DC" },
  { eventId: "4769", description: "Kerberos service ticket requested", category: "Kerberos", notes: "Access to specific service" },
  { eventId: "4771", description: "Kerberos pre-auth failed", category: "Kerberos", notes: "Possible password spray" },
  { eventId: "4776", description: "NTLM authentication", category: "Authentication", notes: "Legacy NTLM authentication" },
  { eventId: "5140", description: "Network share accessed", category: "Object Access", notes: "SMB share access" },
  { eventId: "5145", description: "Network share object checked", category: "Object Access", notes: "Share permission check" },
  { eventId: "5156", description: "Connection allowed by firewall", category: "Network", notes: "Allowed network connection" },
  { eventId: "5157", description: "Connection blocked by firewall", category: "Network", notes: "Blocked network connection" },
];

// Network Configuration
const networkConfiguration = [
  {
    topic: "IP Configuration",
    commands: [
      { cmd: "ipconfig /all", desc: "Full IP configuration" },
      { cmd: "Get-NetIPConfiguration", desc: "PowerShell IP config" },
      { cmd: "Get-NetIPAddress", desc: "List all IP addresses" },
      { cmd: "netsh interface ip show config", desc: "Netsh IP config" },
    ],
  },
  {
    topic: "DNS",
    commands: [
      { cmd: "ipconfig /displaydns", desc: "Show DNS cache" },
      { cmd: "ipconfig /flushdns", desc: "Clear DNS cache" },
      { cmd: "Get-DnsClientCache", desc: "PowerShell DNS cache" },
      { cmd: "Resolve-DnsName google.com", desc: "DNS lookup" },
      { cmd: "nslookup -type=any domain.com", desc: "Advanced DNS query" },
    ],
  },
  {
    topic: "Network Connections",
    commands: [
      { cmd: "netstat -ano", desc: "All connections with PIDs" },
      { cmd: "netstat -b", desc: "Connections with process names" },
      { cmd: "Get-NetTCPConnection", desc: "PowerShell TCP connections" },
      { cmd: "Get-NetUDPEndpoint", desc: "PowerShell UDP endpoints" },
    ],
  },
  {
    topic: "Routing",
    commands: [
      { cmd: "route print", desc: "Display routing table" },
      { cmd: "Get-NetRoute", desc: "PowerShell routing table" },
      { cmd: "tracert hostname", desc: "Trace route to host" },
      { cmd: "pathping hostname", desc: "Combined ping and tracert" },
    ],
  },
  {
    topic: "Network Shares",
    commands: [
      { cmd: "net share", desc: "List local shares" },
      { cmd: "net use", desc: "List mapped drives" },
      { cmd: "Get-SmbShare", desc: "PowerShell list shares" },
      { cmd: "Get-SmbConnection", desc: "Active SMB connections" },
    ],
  },
  {
    topic: "Firewall",
    commands: [
      { cmd: "netsh advfirewall show allprofiles", desc: "Firewall status" },
      { cmd: "Get-NetFirewallProfile", desc: "PowerShell firewall profiles" },
      { cmd: "Get-NetFirewallRule | Where Enabled -eq True", desc: "Active rules" },
      { cmd: "netsh advfirewall firewall show rule name=all", desc: "All firewall rules" },
    ],
  },
];

// PowerShell Security Commands
const powershellSecurityCommands = [
  {
    category: "User & Group Management",
    commands: [
      { cmd: "Get-LocalUser", desc: "List local users" },
      { cmd: "Get-LocalGroup", desc: "List local groups" },
      { cmd: "Get-LocalGroupMember Administrators", desc: "List admin group members" },
      { cmd: "New-LocalUser -Name 'Test' -NoPassword", desc: "Create user" },
      { cmd: "Add-LocalGroupMember -Group 'Users' -Member 'Test'", desc: "Add to group" },
      { cmd: "Disable-LocalUser -Name 'Test'", desc: "Disable user" },
    ],
  },
  {
    category: "Process Analysis",
    commands: [
      { cmd: "Get-Process | Sort CPU -Descending | Select -First 10", desc: "Top CPU processes" },
      { cmd: "Get-Process | Where {$_.Path} | Select Name, Path", desc: "Processes with paths" },
      { cmd: "Get-CimInstance Win32_Process | Select Name, CommandLine", desc: "Process command lines" },
      { cmd: "Get-Process -IncludeUserName", desc: "Processes with owners" },
      { cmd: "Stop-Process -Name notepad -Force", desc: "Kill process by name" },
    ],
  },
  {
    category: "Network Security",
    commands: [
      { cmd: "Get-NetTCPConnection -State Established", desc: "Active connections" },
      { cmd: "Get-NetTCPConnection | Where RemotePort -eq 443", desc: "HTTPS connections" },
      { cmd: "Test-NetConnection -ComputerName host -Port 445", desc: "Test port connectivity" },
      { cmd: "Get-NetFirewallRule -Direction Inbound -Enabled True", desc: "Inbound firewall rules" },
    ],
  },
  {
    category: "File Security",
    commands: [
      { cmd: "Get-Acl C:\\folder | Format-List", desc: "View ACL details" },
      { cmd: "Get-ChildItem -Recurse -Hidden", desc: "Find hidden files" },
      { cmd: "Get-ChildItem -Recurse | Where {$_.Attributes -band [IO.FileAttributes]::Hidden}", desc: "Hidden files (alt)" },
      { cmd: "Get-FileHash -Algorithm SHA256 file.exe", desc: "Get file hash" },
      { cmd: "Get-AuthenticodeSignature file.exe", desc: "Check digital signature" },
    ],
  },
  {
    category: "Service Management",
    commands: [
      { cmd: "Get-Service | Where Status -eq Running", desc: "Running services" },
      { cmd: "Get-WmiObject Win32_Service | Select Name, PathName, StartName", desc: "Service details" },
      { cmd: "Get-Service | Where {$_.StartType -eq 'Automatic'}", desc: "Auto-start services" },
      { cmd: "Set-Service -Name Spooler -StartupType Disabled", desc: "Disable service" },
    ],
  },
  {
    category: "Event Log Analysis",
    commands: [
      { cmd: "Get-EventLog -LogName Security -Newest 100", desc: "Recent security events" },
      { cmd: "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624}", desc: "Successful logons" },
      { cmd: "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 50", desc: "Failed logons" },
      { cmd: "Get-WinEvent -FilterHashtable @{LogName='System';Level=2}", desc: "System errors" },
    ],
  },
  {
    category: "Scheduled Tasks",
    commands: [
      { cmd: "Get-ScheduledTask | Where State -eq Ready", desc: "Active scheduled tasks" },
      { cmd: "Get-ScheduledTask | Get-ScheduledTaskInfo", desc: "Task run history" },
      { cmd: "Export-ScheduledTask -TaskName 'TaskName'", desc: "Export task as XML" },
      { cmd: "Unregister-ScheduledTask -TaskName 'TaskName'", desc: "Remove task" },
    ],
  },
  {
    category: "Registry Security",
    commands: [
      { cmd: "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", desc: "Startup programs" },
      { cmd: "Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", desc: "Installed programs" },
      { cmd: "Test-Path 'HKLM:\\SOFTWARE\\Malware'", desc: "Check registry path exists" },
      { cmd: "Get-Acl HKLM:\\SOFTWARE | Format-List", desc: "Registry ACL" },
    ],
  },
];

// Windows Hardening Checklist
const hardeningChecklist = [
  {
    category: "User Accounts",
    items: [
      "Rename or disable built-in Administrator account",
      "Disable Guest account",
      "Enforce strong password policy (14+ characters, complexity)",
      "Enable account lockout after 5-10 failed attempts",
      "Use separate admin accounts (not daily use accounts)",
      "Implement Managed Service Accounts where possible",
      "Enable MFA for all privileged accounts",
      "Regular review of group memberships",
    ],
  },
  {
    category: "Network Security",
    items: [
      "Enable Windows Firewall on all profiles",
      "Block inbound SMB (port 445) from internet",
      "Disable NetBIOS and LLMNR if not needed",
      "Enable SMB signing",
      "Disable SMBv1 protocol",
      "Use IPsec for sensitive communications",
      "Segment networks appropriately",
      "Monitor outbound connections",
    ],
  },
  {
    category: "System Configuration",
    items: [
      "Enable Secure Boot and UEFI",
      "Enable BitLocker on all drives",
      "Keep system and software updated",
      "Disable unnecessary services",
      "Remove unnecessary features/roles",
      "Configure AppLocker or WDAC policies",
      "Enable Credential Guard on supported hardware",
      "Configure Windows Defender properly",
    ],
  },
  {
    category: "Logging & Monitoring",
    items: [
      "Enable advanced audit policy",
      "Configure PowerShell logging (Script Block, Module, Transcription)",
      "Enable command-line process auditing (Event 4688)",
      "Forward logs to SIEM",
      "Monitor for suspicious Event IDs",
      "Install and configure Sysmon",
      "Set appropriate log retention periods",
      "Alert on critical events",
    ],
  },
  {
    category: "Endpoint Protection",
    items: [
      "Keep Windows Defender definitions updated",
      "Enable real-time protection",
      "Configure Attack Surface Reduction rules",
      "Enable cloud-delivered protection",
      "Enable Controlled Folder Access (ransomware protection)",
      "Configure SmartScreen",
      "Use application whitelisting",
      "Enable Exploit Protection",
    ],
  },
];

// Common Windows Ports
const commonPorts = [
  { port: "20-21", protocol: "TCP", service: "FTP", notes: "File Transfer Protocol (avoid - use SFTP)" },
  { port: "22", protocol: "TCP", service: "SSH", notes: "Secure Shell (OpenSSH on modern Windows)" },
  { port: "23", protocol: "TCP", service: "Telnet", notes: "Unsecure - should be disabled" },
  { port: "25", protocol: "TCP", service: "SMTP", notes: "Email relay" },
  { port: "53", protocol: "TCP/UDP", service: "DNS", notes: "Domain Name System" },
  { port: "67-68", protocol: "UDP", service: "DHCP", notes: "Dynamic Host Configuration Protocol" },
  { port: "80", protocol: "TCP", service: "HTTP", notes: "Web traffic (unencrypted)" },
  { port: "88", protocol: "TCP/UDP", service: "Kerberos", notes: "AD authentication" },
  { port: "123", protocol: "UDP", service: "NTP", notes: "Network Time Protocol" },
  { port: "135", protocol: "TCP", service: "RPC Endpoint Mapper", notes: "Windows RPC - often targeted" },
  { port: "137-139", protocol: "TCP/UDP", service: "NetBIOS", notes: "Legacy name service - consider disabling" },
  { port: "389", protocol: "TCP/UDP", service: "LDAP", notes: "Active Directory queries" },
  { port: "443", protocol: "TCP", service: "HTTPS", notes: "Encrypted web traffic" },
  { port: "445", protocol: "TCP", service: "SMB", notes: "File sharing - major attack vector" },
  { port: "464", protocol: "TCP/UDP", service: "Kerberos Password", notes: "Kerberos password change" },
  { port: "636", protocol: "TCP", service: "LDAPS", notes: "LDAP over SSL" },
  { port: "3268-3269", protocol: "TCP", service: "Global Catalog", notes: "AD Global Catalog queries" },
  { port: "3389", protocol: "TCP", service: "RDP", notes: "Remote Desktop - high value target" },
  { port: "5985", protocol: "TCP", service: "WinRM HTTP", notes: "PowerShell Remoting" },
  { port: "5986", protocol: "TCP", service: "WinRM HTTPS", notes: "PowerShell Remoting (encrypted)" },
];

// Active Directory Basics
const activeDirectoryBasics = [
  {
    component: "Domain Controller (DC)",
    description: "Server hosting Active Directory services",
    keyPoints: [
      "Stores directory database (NTDS.dit)",
      "Handles authentication requests",
      "Replicates data to other DCs",
      "Hosts DNS for AD",
    ],
  },
  {
    component: "Organizational Units (OUs)",
    description: "Containers for organizing AD objects",
    keyPoints: [
      "Can contain users, groups, computers",
      "Group Policy can be linked to OUs",
      "Delegation of admin rights at OU level",
      "Hierarchical structure",
    ],
  },
  {
    component: "Security Groups",
    description: "Collections of users/computers for permission assignment",
    keyPoints: [
      "Domain Local, Global, Universal scopes",
      "Used for resource access control",
      "Nested group memberships",
      "Critical groups: Domain Admins, Enterprise Admins",
    ],
  },
  {
    component: "Group Policy Objects (GPOs)",
    description: "Policy settings applied to users/computers",
    keyPoints: [
      "Computer and User configuration sections",
      "Linked to Sites, Domains, OUs",
      "Inheritance and precedence rules",
      "gpresult /r to check applied policies",
    ],
  },
  {
    component: "LDAP/LDAPS",
    description: "Protocol for querying and modifying AD",
    keyPoints: [
      "Port 389 (LDAP) and 636 (LDAPS)",
      "Distinguished Names (DN) identify objects",
      "Attributes store object properties",
      "Tools: ldapsearch, ADExplorer",
    ],
  },
  {
    component: "Kerberos",
    description: "Primary authentication protocol for AD",
    keyPoints: [
      "Ticket-based authentication",
      "KDC on Domain Controller",
      "TGT and Service Tickets",
      "Vulnerable to Kerberoasting, Pass-the-Ticket",
    ],
  },
];

const ACCENT_COLOR = "#0078d4";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "NTFS",
    question: "What is the default file system for modern Windows installations?",
    options: ["NTFS", "FAT32", "ext4", "APFS"],
    correctAnswer: 0,
    explanation: "NTFS is the default file system for modern Windows versions.",
  },
  {
    id: 2,
    topic: "NTFS",
    question: "Which NTFS feature allows data to be hidden within files?",
    options: ["Alternate Data Streams (ADS)", "Journaling", "Compression", "Shadow Copies"],
    correctAnswer: 0,
    explanation: "Alternate Data Streams can store hidden data alongside a file.",
  },
  {
    id: 3,
    topic: "NTFS",
    question: "NTFS permissions are implemented using:",
    options: ["Access Control Lists (ACLs)", "File ownership only", "Password-protected folders", "BIOS settings"],
    correctAnswer: 0,
    explanation: "NTFS uses ACLs to define detailed permissions.",
  },
  {
    id: 4,
    topic: "NTFS",
    question: "What does MFT stand for in NTFS?",
    options: ["Master File Table", "Main File Tree", "Microsoft File Tracker", "Metadata File Table"],
    correctAnswer: 0,
    explanation: "The MFT stores metadata for files and directories in NTFS.",
  },
  {
    id: 5,
    topic: "NTFS",
    question: "Which character is used as the path separator in Windows?",
    options: ["Backslash (\\)", "Forward slash (/)", "Colon (:)", "Pipe (|)"],
    correctAnswer: 0,
    explanation: "Windows paths use the backslash character.",
  },
  {
    id: 6,
    topic: "NTFS",
    question: "Drive letters like C: and D: represent:",
    options: ["Volumes", "User accounts", "Services", "Registry hives"],
    correctAnswer: 0,
    explanation: "Drive letters map to volumes or partitions.",
  },
  {
    id: 7,
    topic: "NTFS",
    question: "What Windows feature provides file-level encryption on NTFS?",
    options: ["EFS (Encrypting File System)", "BitLocker", "Secure Boot", "SmartScreen"],
    correctAnswer: 0,
    explanation: "EFS provides file-level encryption on NTFS volumes.",
  },
  {
    id: 8,
    topic: "NTFS",
    question: "Which file attribute hides files from normal directory listings?",
    options: ["Hidden", "Archive", "System", "Read-only"],
    correctAnswer: 0,
    explanation: "The Hidden attribute prevents files from appearing in normal listings.",
  },
  {
    id: 9,
    topic: "NTFS",
    question: "Which command checks a disk for file system errors?",
    options: ["chkdsk", "dir", "tasklist", "netstat"],
    correctAnswer: 0,
    explanation: "chkdsk scans and repairs file system issues.",
  },
  {
    id: 10,
    topic: "NTFS",
    question: "Which NTFS capability is not supported by FAT32?",
    options: ["File permissions", "Basic file storage", "Short file names", "Bootable partitions"],
    correctAnswer: 0,
    explanation: "FAT32 does not support NTFS-style permissions.",
  },
  {
    id: 11,
    topic: "Registry",
    question: "Which registry hive stores system-wide settings?",
    options: ["HKEY_LOCAL_MACHINE (HKLM)", "HKEY_CURRENT_USER (HKCU)", "HKEY_USERS (HKU)", "HKEY_CLASSES_ROOT (HKCR)"],
    correctAnswer: 0,
    explanation: "HKLM holds system-wide configuration.",
  },
  {
    id: 12,
    topic: "Registry",
    question: "Which registry hive stores the current user's settings?",
    options: ["HKEY_CURRENT_USER (HKCU)", "HKEY_LOCAL_MACHINE (HKLM)", "HKEY_CURRENT_CONFIG (HKCC)", "HKEY_CLASSES_ROOT (HKCR)"],
    correctAnswer: 0,
    explanation: "HKCU stores settings for the currently logged-in user.",
  },
  {
    id: 13,
    topic: "Registry",
    question: "Which registry hive is commonly used for file associations?",
    options: ["HKEY_CLASSES_ROOT (HKCR)", "HKEY_USERS (HKU)", "HKEY_CURRENT_CONFIG (HKCC)", "HKEY_LOCAL_MACHINE (HKLM)"],
    correctAnswer: 0,
    explanation: "HKCR manages file type associations and COM registrations.",
  },
  {
    id: 14,
    topic: "Registry",
    question: "Which hive contains all user profiles on the system?",
    options: ["HKEY_USERS (HKU)", "HKEY_CURRENT_USER (HKCU)", "HKEY_LOCAL_MACHINE (HKLM)", "HKEY_CLASSES_ROOT (HKCR)"],
    correctAnswer: 0,
    explanation: "HKU stores per-user hives for all profiles.",
  },
  {
    id: 15,
    topic: "Registry",
    question: "Which hive represents the current hardware profile?",
    options: ["HKEY_CURRENT_CONFIG (HKCC)", "HKEY_LOCAL_MACHINE (HKLM)", "HKEY_CURRENT_USER (HKCU)", "HKEY_USERS (HKU)"],
    correctAnswer: 0,
    explanation: "HKCC reflects the current hardware profile.",
  },
  {
    id: 16,
    topic: "Registry",
    question: "What is the GUI tool for editing the Windows Registry?",
    options: ["regedit.exe", "services.msc", "eventvwr.msc", "gpedit.msc"],
    correctAnswer: 0,
    explanation: "regedit.exe is the Registry Editor.",
  },
  {
    id: 17,
    topic: "Registry",
    question: "Which command-line tool can query and edit the Registry?",
    options: ["reg.exe", "sc.exe", "whoami", "diskpart"],
    correctAnswer: 0,
    explanation: "reg.exe provides command-line registry access.",
  },
  {
    id: 18,
    topic: "Registry",
    question: "Which file stores a user's registry hive on disk?",
    options: ["NTUSER.DAT", "SAM", "SYSTEM", "SECURITY"],
    correctAnswer: 0,
    explanation: "NTUSER.DAT contains the per-user registry hive.",
  },
  {
    id: 19,
    topic: "Registry",
    question: "The Run and RunOnce keys are commonly used for:",
    options: ["Startup programs", "Disk encryption", "Time synchronization", "Firewall rules"],
    correctAnswer: 0,
    explanation: "Run and RunOnce control startup execution.",
  },
  {
    id: 20,
    topic: "Registry",
    question: "Which registry data type stores a 32-bit integer?",
    options: ["REG_DWORD", "REG_SZ", "REG_BINARY", "REG_MULTI_SZ"],
    correctAnswer: 0,
    explanation: "REG_DWORD is a 32-bit integer value.",
  },
  {
    id: 21,
    topic: "Services",
    question: "What does services.msc open?",
    options: ["Services management console", "Event Viewer", "Registry Editor", "Task Scheduler"],
    correctAnswer: 0,
    explanation: "services.msc opens the Services console.",
  },
  {
    id: 22,
    topic: "Services",
    question: "Which service account has the highest privileges?",
    options: ["LocalSystem", "LocalService", "NetworkService", "Guest"],
    correctAnswer: 0,
    explanation: "LocalSystem has extensive privileges on the local machine.",
  },
  {
    id: 23,
    topic: "Services",
    question: "Which service account is the least privileged?",
    options: ["LocalService", "NetworkService", "LocalSystem", "Administrator"],
    correctAnswer: 0,
    explanation: "LocalService has minimal privileges.",
  },
  {
    id: 24,
    topic: "Services",
    question: "Which command-line tool manages Windows services?",
    options: ["sc.exe", "reg.exe", "icacls", "netstat"],
    correctAnswer: 0,
    explanation: "sc.exe is used for service control.",
  },
  {
    id: 25,
    topic: "Services",
    question: "Which PowerShell cmdlet lists Windows services?",
    options: ["Get-Service", "Get-Process", "Get-EventLog", "Get-Content"],
    correctAnswer: 0,
    explanation: "Get-Service lists installed services.",
  },
  {
    id: 26,
    topic: "Services",
    question: "Windows services typically run in:",
    options: ["Session 0", "Session 1", "Session 2", "Session 3"],
    correctAnswer: 0,
    explanation: "Services run in Session 0, isolated from user sessions.",
  },
  {
    id: 27,
    topic: "Services",
    question: "Which startup type begins after a short boot delay?",
    options: ["Automatic (Delayed)", "Manual", "Disabled", "Boot"],
    correctAnswer: 0,
    explanation: "Automatic (Delayed) starts shortly after boot.",
  },
  {
    id: 28,
    topic: "Services",
    question: "Service dependencies are used to:",
    options: [
      "Ensure required services start before others",
      "Set user permissions",
      "Encrypt service binaries",
      "Disable logging",
    ],
    correctAnswer: 0,
    explanation: "Dependencies control service start order and prerequisites.",
  },
  {
    id: 29,
    topic: "Services",
    question: "Service configurations are stored under which registry path?",
    options: [
      "HKLM\\SYSTEM\\CurrentControlSet\\Services",
      "HKCU\\Software\\Services",
      "HKLM\\SOFTWARE\\Classes",
      "HKU\\Default\\Services",
    ],
    correctAnswer: 0,
    explanation: "Service settings are under HKLM\\SYSTEM\\CurrentControlSet\\Services.",
  },
  {
    id: 30,
    topic: "Services",
    question: "Misconfigured service permissions can lead to:",
    options: ["Privilege escalation", "Network throttling", "Time drift", "File compression"],
    correctAnswer: 0,
    explanation: "Weak service permissions are a common escalation path.",
  },
  {
    id: 31,
    topic: "Users and Permissions",
    question: "What is the primary purpose of User Account Control (UAC)?",
    options: [
      "Require elevation for administrative actions",
      "Disable antivirus",
      "Encrypt disks",
      "Manage DNS records",
    ],
    correctAnswer: 0,
    explanation: "UAC prompts for elevation to reduce unauthorized changes.",
  },
  {
    id: 32,
    topic: "Users and Permissions",
    question: "Which built-in group has administrative rights on a Windows machine?",
    options: ["Administrators", "Users", "Guests", "Remote Desktop Users"],
    correctAnswer: 0,
    explanation: "Members of the Administrators group have elevated rights.",
  },
  {
    id: 33,
    topic: "Users and Permissions",
    question: "What does SID stand for?",
    options: ["Security Identifier", "System Identity Descriptor", "Secure ID", "Session Identifier"],
    correctAnswer: 0,
    explanation: "A SID uniquely identifies a user or group.",
  },
  {
    id: 34,
    topic: "Users and Permissions",
    question: "Which permission rule takes precedence in NTFS?",
    options: ["Explicit deny", "Inherited allow", "Explicit allow", "Inherited deny"],
    correctAnswer: 0,
    explanation: "Explicit deny entries override allow entries.",
  },
  {
    id: 35,
    topic: "Users and Permissions",
    question: "ACLs are made up of:",
    options: ["Access Control Entries (ACEs)", "User tokens", "Service descriptors", "Registry keys"],
    correctAnswer: 0,
    explanation: "ACLs consist of ACEs that grant or deny permissions.",
  },
  {
    id: 36,
    topic: "Users and Permissions",
    question: "Which tool manages local users and groups on Windows Pro?",
    options: ["lusrmgr.msc", "taskschd.msc", "diskmgmt.msc", "perfmon.msc"],
    correctAnswer: 0,
    explanation: "lusrmgr.msc opens Local Users and Groups.",
  },
  {
    id: 37,
    topic: "Users and Permissions",
    question: "Where are user profiles stored by default?",
    options: ["C:\\Users", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Temp"],
    correctAnswer: 0,
    explanation: "User profiles live under C:\\Users by default.",
  },
  {
    id: 38,
    topic: "Users and Permissions",
    question: "A Windows access token represents:",
    options: ["A user's security context", "A registry key", "A service dependency", "A disk partition"],
    correctAnswer: 0,
    explanation: "Tokens describe a user's identity and privileges.",
  },
  {
    id: 39,
    topic: "Users and Permissions",
    question: "The principle of least privilege means:",
    options: [
      "Grant only the permissions needed",
      "Grant admin rights to all",
      "Disable auditing",
      "Use shared accounts",
    ],
    correctAnswer: 0,
    explanation: "Least privilege minimizes access to what is required.",
  },
  {
    id: 40,
    topic: "Users and Permissions",
    question: "Which built-in account is typically disabled by default?",
    options: ["Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount"],
    correctAnswer: 0,
    explanation: "The built-in Administrator account is disabled by default on modern Windows.",
  },
  {
    id: 41,
    topic: "Processes",
    question: "Which process commonly hosts multiple Windows services?",
    options: ["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe"],
    correctAnswer: 0,
    explanation: "svchost.exe is a shared host for many services.",
  },
  {
    id: 42,
    topic: "Processes",
    question: "What is the role of explorer.exe?",
    options: ["Windows shell and file manager", "Firewall service", "Update manager", "Registry editor"],
    correctAnswer: 0,
    explanation: "explorer.exe provides the desktop UI and file manager.",
  },
  {
    id: 43,
    topic: "Processes",
    question: "Which process handles authentication and security policies?",
    options: ["lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe"],
    correctAnswer: 0,
    explanation: "LSASS manages authentication and local security policy.",
  },
  {
    id: 44,
    topic: "Processes",
    question: "Which process manages user logon and logoff?",
    options: ["winlogon.exe", "services.exe", "csrss.exe", "taskhostw.exe"],
    correctAnswer: 0,
    explanation: "winlogon.exe handles logon and session setup.",
  },
  {
    id: 45,
    topic: "Processes",
    question: "What file is used for virtual memory paging?",
    options: ["pagefile.sys", "boot.ini", "swapfile.sys", "hiberfil.sys"],
    correctAnswer: 0,
    explanation: "pagefile.sys is used for virtual memory paging.",
  },
  {
    id: 46,
    topic: "Processes",
    question: "The System process (PID 4) primarily represents:",
    options: ["Kernel and drivers", "User shell", "Network stack only", "Windows Update"],
    correctAnswer: 0,
    explanation: "The System process is tied to kernel and driver activity.",
  },
  {
    id: 47,
    topic: "Tools",
    question: "Which command opens Task Manager?",
    options: ["taskmgr.exe", "services.msc", "regedit.exe", "perfmon.exe"],
    correctAnswer: 0,
    explanation: "taskmgr.exe launches Task Manager.",
  },
  {
    id: 48,
    topic: "Tools",
    question: "Which Sysinternals tool provides advanced process inspection?",
    options: ["Process Explorer", "TCPView", "Autoruns", "Sigcheck"],
    correctAnswer: 0,
    explanation: "Process Explorer shows detailed process information.",
  },
  {
    id: 49,
    topic: "Tools",
    question: "Which Sysinternals tool tracks file, registry, and process activity?",
    options: ["Process Monitor", "Process Explorer", "PsExec", "TCPView"],
    correctAnswer: 0,
    explanation: "Process Monitor (procmon) provides detailed activity tracing.",
  },
  {
    id: 50,
    topic: "Tools",
    question: "Which tool opens the Windows Event Viewer?",
    options: ["eventvwr.msc", "services.msc", "taskschd.msc", "diskmgmt.msc"],
    correctAnswer: 0,
    explanation: "eventvwr.msc opens Event Viewer.",
  },
  {
    id: 51,
    topic: "Command Line",
    question: "Which command shows IP configuration?",
    options: ["ipconfig", "whoami", "net user", "systeminfo"],
    correctAnswer: 0,
    explanation: "ipconfig displays network configuration details.",
  },
  {
    id: 52,
    topic: "Command Line",
    question: "Which command lists active network connections?",
    options: ["netstat", "tasklist", "dir", "ping"],
    correctAnswer: 0,
    explanation: "netstat shows active connections and listening ports.",
  },
  {
    id: 53,
    topic: "Command Line",
    question: "Which command is commonly used to query DNS records?",
    options: ["nslookup", "chkdsk", "sc", "icacls"],
    correctAnswer: 0,
    explanation: "nslookup queries DNS servers.",
  },
  {
    id: 54,
    topic: "Command Line",
    question: "Which command tests basic network connectivity?",
    options: ["ping", "tasklist", "reg", "gpresult"],
    correctAnswer: 0,
    explanation: "ping checks reachability to a host.",
  },
  {
    id: 55,
    topic: "Command Line",
    question: "Which command traces the network path to a host?",
    options: ["tracert", "netstat", "dir", "format"],
    correctAnswer: 0,
    explanation: "tracert shows each hop to a destination.",
  },
  {
    id: 56,
    topic: "Command Line",
    question: "Which command shows the current user and groups?",
    options: ["whoami", "ipconfig", "hostname", "net use"],
    correctAnswer: 0,
    explanation: "whoami prints the current user and groups.",
  },
  {
    id: 57,
    topic: "Command Line",
    question: "Which command outputs OS and hardware details?",
    options: ["systeminfo", "tree", "dir", "cls"],
    correctAnswer: 0,
    explanation: "systeminfo prints OS and hardware information.",
  },
  {
    id: 58,
    topic: "Command Line",
    question: "Which command runs a process as another user?",
    options: ["runas", "taskkill", "net share", "shutdown"],
    correctAnswer: 0,
    explanation: "runas starts a process with alternate credentials.",
  },
  {
    id: 59,
    topic: "Command Line",
    question: "Which command modifies NTFS permissions from the CLI?",
    options: ["icacls", "attrib", "type", "copy"],
    correctAnswer: 0,
    explanation: "icacls manages NTFS ACLs from the command line.",
  },
  {
    id: 60,
    topic: "PowerShell",
    question: "Which PowerShell cmdlet lists running processes?",
    options: ["Get-Process", "Get-Service", "Get-EventLog", "Get-ChildItem"],
    correctAnswer: 0,
    explanation: "Get-Process shows running processes.",
  },
  {
    id: 61,
    topic: "Security",
    question: "Which built-in tool provides antivirus protection?",
    options: ["Microsoft Defender", "BitLocker", "SmartScreen", "UAC"],
    correctAnswer: 0,
    explanation: "Microsoft Defender provides built-in antivirus protection.",
  },
  {
    id: 62,
    topic: "Security",
    question: "Windows Defender Firewall is a:",
    options: ["Host-based firewall", "Disk encryption tool", "Process monitor", "Registry editor"],
    correctAnswer: 0,
    explanation: "Windows Defender Firewall controls inbound and outbound traffic.",
  },
  {
    id: 63,
    topic: "Security",
    question: "Which Windows feature provides full disk encryption?",
    options: ["BitLocker", "EFS", "UAC", "SmartScreen"],
    correctAnswer: 0,
    explanation: "BitLocker provides full disk encryption.",
  },
  {
    id: 64,
    topic: "Security",
    question: "SmartScreen helps by:",
    options: ["Warning about untrusted downloads and apps", "Disabling updates", "Encrypting files", "Managing services"],
    correctAnswer: 0,
    explanation: "SmartScreen uses reputation checks to warn about risky downloads.",
  },
  {
    id: 65,
    topic: "Logging",
    question: "Windows Security Event ID 4624 indicates:",
    options: ["Successful logon", "Failed logon", "Service install", "System shutdown"],
    correctAnswer: 0,
    explanation: "Event ID 4624 is a successful logon event.",
  },
  {
    id: 66,
    topic: "Logging",
    question: "Windows Security Event ID 4625 indicates:",
    options: ["Failed logon", "Successful logon", "Account lockout", "Time change"],
    correctAnswer: 0,
    explanation: "Event ID 4625 is a failed logon event.",
  },
  {
    id: 67,
    topic: "Logging",
    question: "Which Windows log stores authentication events?",
    options: ["Security", "Application", "System", "Setup"],
    correctAnswer: 0,
    explanation: "The Security log stores authentication and authorization events.",
  },
  {
    id: 68,
    topic: "Networking",
    question: "SMB typically uses which TCP port?",
    options: ["445", "80", "22", "3389"],
    correctAnswer: 0,
    explanation: "SMB uses TCP port 445.",
  },
  {
    id: 69,
    topic: "Networking",
    question: "Remote Desktop Protocol (RDP) typically uses which TCP port?",
    options: ["3389", "443", "21", "53"],
    correctAnswer: 0,
    explanation: "RDP uses TCP port 3389.",
  },
  {
    id: 70,
    topic: "Networking",
    question: "Where is the Windows hosts file located?",
    options: [
      "C:\\Windows\\System32\\drivers\\etc\\hosts",
      "C:\\Windows\\System32\\hosts",
      "C:\\Windows\\Temp\\hosts",
      "C:\\Users\\Public\\hosts",
    ],
    correctAnswer: 0,
    explanation: "The hosts file is under C:\\Windows\\System32\\drivers\\etc.",
  },
  {
    id: 71,
    topic: "Maintenance",
    question: "Which Windows component handles system updates?",
    options: ["Windows Update", "Task Scheduler", "Registry Editor", "Disk Cleanup"],
    correctAnswer: 0,
    explanation: "Windows Update manages OS patching and updates.",
  },
  {
    id: 72,
    topic: "Tools",
    question: "Which tool opens Task Scheduler?",
    options: ["taskschd.msc", "services.msc", "eventvwr.msc", "diskmgmt.msc"],
    correctAnswer: 0,
    explanation: "taskschd.msc opens Task Scheduler.",
  },
  {
    id: 73,
    topic: "Policies",
    question: "Which tool edits Local Group Policy?",
    options: ["gpedit.msc", "lusrmgr.msc", "mmc.exe", "regedit.exe"],
    correctAnswer: 0,
    explanation: "gpedit.msc opens the Local Group Policy Editor.",
  },
  {
    id: 74,
    topic: "Time",
    question: "Which service provides time synchronization?",
    options: ["Windows Time (w32time)", "Print Spooler", "DNS Client", "Remote Registry"],
    correctAnswer: 0,
    explanation: "Windows Time (w32time) synchronizes system time.",
  },
  {
    id: 75,
    topic: "Environment",
    question: "What does the %SYSTEMROOT% environment variable point to?",
    options: ["Windows installation directory", "User profile directory", "Temporary files", "Program Files"],
    correctAnswer: 0,
    explanation: "%SYSTEMROOT% points to the Windows directory (typically C:\\Windows).",
  },
];

export default function WindowsBasicsPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [quizPool] = React.useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const accent = "#0078d4"; // Windows blue

  // Section navigation items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <InfoIcon /> },
    { id: "version-history", label: "Version History", icon: <HistoryIcon /> },
    { id: "boot-process", label: "Boot Process", icon: <SpeedIcon /> },
    { id: "core-concepts", label: "Core Concepts", icon: <DesktopWindowsIcon /> },
    { id: "architecture", label: "Architecture", icon: <AccountTreeIcon /> },
    { id: "security-features", label: "Security Features", icon: <ShieldIcon /> },
    { id: "directories", label: "Directories", icon: <FolderIcon /> },
    { id: "registry-keys", label: "Registry Keys", icon: <KeyIcon /> },
    { id: "cmd-commands", label: "CMD Commands", icon: <TerminalIcon /> },
    { id: "powershell", label: "PowerShell", icon: <TerminalIcon /> },
    { id: "powershell-security", label: "PS Security", icon: <SecurityIcon /> },
    { id: "processes", label: "Processes", icon: <MemoryIcon /> },
    { id: "networking", label: "Networking", icon: <NetworkCheckIcon /> },
    { id: "common-ports", label: "Common Ports", icon: <RouterIcon /> },
    { id: "active-directory", label: "Active Directory", icon: <DnsIcon /> },
    { id: "group-policy", label: "Group Policy", icon: <PolicyIcon /> },
    { id: "security-events", label: "Security Events", icon: <SecurityIcon /> },
    { id: "forensic-artifacts", label: "Forensics", icon: <FindInPageIcon /> },
    { id: "hardening", label: "Hardening", icon: <GppGoodIcon /> },
    { id: "shortcuts", label: "Shortcuts", icon: <KeyboardArrowUpIcon /> },
    { id: "tools", label: "Tools", icon: <BuildIcon /> },
    { id: "environment-vars", label: "Environment Vars", icon: <SettingsIcon /> },
    { id: "pro-tips", label: "Pro Tips", icon: <TipsAndUpdatesIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Progress calculation
  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `Windows Fundamentals learning page - Comprehensive guide to the Microsoft Windows operating system for security professionals, system administrators, and IT practitioners. This in-depth resource covers core concepts including the NTFS file system, Windows Registry, Services architecture, Users & Permissions model, Command Line interfaces (CMD and PowerShell), and Process/Memory management. Includes detailed reference tables for important directory locations, security-critical registry keys, essential CMD commands with PowerShell equivalents, critical system processes, Windows Security Event IDs for detection and forensics, and productivity keyboard shortcuts.`;

  const commandCategories = [...new Set(essentialCommands.map(c => c.category))];

  // Sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Windows Fundamentals" pageContext={pageContext}>
      <Box sx={{ display: "flex", gap: 3, position: "relative" }}>
        {/* Sidebar Navigation */}
        {sidebarNav}

        {/* Main Content */}
        <Container maxWidth="lg" sx={{ py: 4, flex: 1 }}>
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

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#0078d4", 0.15)} 0%, ${alpha("#00a2ed", 0.1)} 100%)`,
            border: `1px solid ${alpha("#0078d4", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `linear-gradient(135deg, ${alpha("#0078d4", 0.1)}, transparent)`,
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #0078d4, #00a2ed)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#0078d4", 0.3)}`,
              }}
            >
              <DesktopWindowsIcon sx={{ fontSize: 45, color: "white" }} />
            </Box>
            <Box>
              <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#0078d4", 0.1), color: "#0078d4" }} />
              <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                Windows Fundamentals
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                Master the Windows operating system from the ground up
              </Typography>
            </Box>
          </Box>
        </Paper>

        {/* Overview Section */}
        <Box id="intro">
          <Paper
            sx={{
              p: 4,
              mb: 5,
              borderRadius: 4,
              bgcolor: alpha(theme.palette.background.paper, 0.6),
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            }}
          >
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <InfoIcon sx={{ color: "#0078d4" }} />
              Overview
            </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Microsoft Windows is the world's most widely deployed desktop operating system, powering over 1 billion devices globally 
            and dominating enterprise environments with approximately 75% market share in corporate settings. Originally released in 1985 
            as a graphical shell for MS-DOS, Windows has evolved into a sophisticated, multi-user, multitasking operating system that 
            forms the backbone of most business IT infrastructure.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            For cybersecurity professionals, understanding Windows fundamentals is not optional—it's essential. Whether you're 
            conducting penetration tests, performing incident response, analyzing malware, or securing enterprise networks, you'll 
            encounter Windows systems at every turn. The operating system's architecture, including its file system (NTFS), registry, 
            service model, user permissions framework, and command-line interfaces, provides both the attack surface that adversaries 
            exploit and the defensive mechanisms that security teams leverage.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            This comprehensive guide covers the core components of Windows that every IT professional and security practitioner must 
            understand. From navigating the file system and managing services to interpreting security events and leveraging PowerShell, 
            these fundamentals form the foundation for more advanced topics like Active Directory, privilege escalation, and Windows 
            internals for reverse engineering.
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>Who This Is For</Typography>
                <Typography variant="body2" color="text.secondary">
                  Security analysts, penetration testers, system administrators, IT support professionals, and anyone beginning their 
                  cybersecurity journey who needs to understand Windows.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Prerequisites</Typography>
                <Typography variant="body2" color="text.secondary">
                  Basic computer literacy and familiarity with general computing concepts. No prior Windows administration experience 
                  required—we start from the basics.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>What You'll Learn</Typography>
                <Typography variant="body2" color="text.secondary">
                  File system navigation, registry structure, service management, user permissions, command-line proficiency, 
                  process analysis, and security event interpretation.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Quick Stats - Updated */}
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { value: "6", label: "Core Concepts", color: "#0078d4", icon: <LayersIcon /> },
            { value: "18", label: "Key Directories", color: "#10b981", icon: <FolderIcon /> },
            { value: "30", label: "Essential Commands", color: "#f59e0b", icon: <TerminalIcon /> },
            { value: "14", label: "Admin Tools", color: "#8b5cf6", icon: <BuildIcon /> },
            { value: "10", label: "Critical Processes", color: "#ef4444", icon: <MemoryIcon /> },
            { value: "12", label: "Security Events", color: "#06b6d4", icon: <SecurityIcon /> },
          ].map((stat) => (
            <Grid item xs={6} md={2} key={stat.label}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha(stat.color, 0.2)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: `0 4px 20px ${alpha(stat.color, 0.15)}`,
                  },
                }}
              >
                <Box sx={{ color: stat.color, mb: 0.5 }}>{stat.icon}</Box>
                <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                  {stat.value}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {stat.label}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Windows Versions Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            WINDOWS VERSIONS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>
        </Box>

        {/* Version History Section */}
        <Box id="version-history">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            📅 Windows Version History
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding which Windows versions you may encounter
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {windowsVersions.map((ver) => (
            <Grid item xs={12} sm={6} md={3} key={ver.version}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha("#0078d4", 0.15)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    borderColor: "#0078d4",
                  },
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0078d4", mb: 0.5 }}>
                  {ver.version}
                </Typography>
                <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                  <Chip label={ver.release} size="small" sx={{ fontSize: "0.65rem", fontWeight: 600 }} />
                  <Chip label={`NT ${ver.kernel}`} size="small" variant="outlined" sx={{ fontSize: "0.65rem", fontFamily: "monospace" }} />
                </Box>
                <Typography variant="caption" color="text.secondary">
                  {ver.notes}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        </Box>

        {/* Boot Process Section */}
        <Box id="boot-process">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🚀 Windows Boot Process
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding how Windows starts - essential for troubleshooting and security analysis
        </Typography>

        <Paper sx={{ p: 3, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#10b981", 0.2)}` }}>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
            {bootProcess.map((step, index) => (
              <Box key={step.step} sx={{ display: "flex", alignItems: "flex-start", flex: "1 1 300px" }}>
                <Box
                  sx={{
                    width: 36,
                    height: 36,
                    borderRadius: "50%",
                    bgcolor: "#10b981",
                    color: "white",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 800,
                    mr: 2,
                    flexShrink: 0,
                  }}
                >
                  {step.step}
                </Box>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{step.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{step.description}</Typography>
                </Box>
                {index < bootProcess.length - 1 && (
                  <Box sx={{ display: { xs: "none", md: "block" }, ml: 2, color: "#10b981", fontWeight: 700 }}>→</Box>
                )}
              </Box>
            ))}
          </Box>
        </Paper>

        {/* Introduction Alert */}
        <Alert 
          severity="info" 
          icon={<InfoIcon />}
          sx={{ mb: 4, borderRadius: 3 }}
        >
          <AlertTitle sx={{ fontWeight: 700 }}>Why Learn Windows Fundamentals?</AlertTitle>
          Windows dominates enterprise environments with over 75% market share in corporate settings. 
          Understanding Windows internals is essential for penetration testing, incident response, 
          malware analysis, and system administration. This guide covers the core concepts you need.
        </Alert>

        </Box>

        {/* Core Concepts */}
        <Box id="core-concepts">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🖥️ Core Windows Concepts
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Fundamental building blocks of the Windows operating system
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          {windowsConcepts.map((concept) => (
            <Grid item xs={12} md={6} key={concept.title}>
              <Paper
                sx={{
                  p: 0,
                  height: "100%",
                  borderRadius: 4,
                  overflow: "hidden",
                  border: `1px solid ${alpha(concept.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 12px 40px ${alpha(concept.color, 0.15)}`,
                  },
                }}
              >
                <Box
                  sx={{
                    p: 2,
                    background: `linear-gradient(135deg, ${alpha(concept.color, 0.15)} 0%, ${alpha(concept.color, 0.05)} 100%)`,
                    borderBottom: `1px solid ${alpha(concept.color, 0.1)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 48,
                        height: 48,
                        borderRadius: 2,
                        background: `linear-gradient(135deg, ${concept.color}, ${alpha(concept.color, 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "white",
                      }}
                    >
                      {concept.icon}
                    </Box>
                    <Box>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {concept.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {concept.description}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
                <Box sx={{ p: 2.5 }}>
                  <List dense>
                    {concept.keyPoints.map((point) => (
                      <ListItem key={point} sx={{ py: 0.3, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ fontSize: 14, color: concept.color }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={point}
                          primaryTypographyProps={{ variant: "body2", lineHeight: 1.4, fontSize: "0.85rem" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                  
                  {/* Details Accordion */}
                  {concept.details && (
                    <Accordion 
                      sx={{ 
                        mt: 1.5, 
                        boxShadow: "none", 
                        bgcolor: alpha(concept.color, 0.03),
                        "&:before": { display: "none" },
                        borderRadius: "8px !important",
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 40 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: concept.color }}>
                          Technical Details
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails sx={{ pt: 0 }}>
                        <List dense>
                          {concept.details.map((detail, i) => (
                            <ListItem key={i} sx={{ py: 0.2, px: 0 }}>
                              <ListItemIcon sx={{ minWidth: 20 }}>
                                <Box sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: concept.color }} />
                              </ListItemIcon>
                              <ListItemText
                                primary={detail}
                                primaryTypographyProps={{ variant: "caption" }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  <Box
                    sx={{
                      mt: 2,
                      p: 1.5,
                      borderRadius: 2,
                      bgcolor: alpha("#f59e0b", 0.05),
                      border: `1px dashed ${alpha("#f59e0b", 0.3)}`,
                    }}
                  >
                    <Typography
                      variant="caption"
                      sx={{ display: "flex", alignItems: "flex-start", gap: 0.5, fontWeight: 500 }}
                    >
                      <SecurityIcon sx={{ fontSize: 14, color: "#f59e0b", mt: 0.2, flexShrink: 0 }} />
                      {concept.securityNote}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Windows Architecture */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            ARCHITECTURE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Architecture Section */}
        <Box id="architecture">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🏗️ Windows Architecture Overview
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding the layered structure of Windows
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          {windowsArchitecture.map((layer) => (
            <Grid item xs={12} md={6} key={layer.layer}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 4,
                  border: `2px solid ${layer.color}`,
                  background: `linear-gradient(135deg, ${alpha(layer.color, 0.05)} 0%, transparent 100%)`,
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <AccountTreeIcon sx={{ color: layer.color, fontSize: 28 }} />
                  <Typography variant="h6" sx={{ fontWeight: 700, color: layer.color }}>
                    {layer.layer}
                  </Typography>
                  <Chip 
                    label={layer.layer === "Kernel Mode" ? "Ring 0" : "Ring 3"} 
                    size="small"
                    sx={{ 
                      bgcolor: alpha(layer.color, 0.1), 
                      color: layer.color,
                      fontWeight: 700,
                      fontSize: "0.7rem",
                    }} 
                  />
                </Box>
                {layer.components.map((comp) => (
                  <Box 
                    key={comp.name} 
                    sx={{ 
                      p: 1.5, 
                      mb: 1, 
                      borderRadius: 2, 
                      bgcolor: alpha(layer.color, 0.05),
                      borderLeft: `3px solid ${layer.color}`,
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                      {comp.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {comp.description}
                    </Typography>
                  </Box>
                ))}
              </Paper>
            </Grid>
          ))}
        </Grid>

        </Box>

        {/* Windows Security Features Section */}
        <Box id="security-features" sx={{ mt: 5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              SECURITY FEATURES
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🛡️ Windows Security Features
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Built-in security technologies that protect Windows systems
          </Typography>

          <Grid container spacing={3} sx={{ mb: 5 }}>
            {windowsSecurityFeatures.map((feature) => (
              <Grid item xs={12} md={6} key={feature.name}>
                <Paper
                  sx={{
                    p: 0,
                    height: "100%",
                    borderRadius: 4,
                    overflow: "hidden",
                    border: `1px solid ${alpha(feature.color, 0.2)}`,
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: `0 12px 40px ${alpha(feature.color, 0.15)}`,
                    },
                  }}
                >
                  <Box
                    sx={{
                      p: 2,
                      background: `linear-gradient(135deg, ${alpha(feature.color, 0.15)} 0%, ${alpha(feature.color, 0.05)} 100%)`,
                      borderBottom: `1px solid ${alpha(feature.color, 0.1)}`,
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 2,
                          background: `linear-gradient(135deg, ${feature.color}, ${alpha(feature.color, 0.7)})`,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          color: "white",
                        }}
                      >
                        {feature.icon}
                      </Box>
                      <Box>
                        <Typography variant="h6" sx={{ fontWeight: 700 }}>
                          {feature.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {feature.description}
                        </Typography>
                      </Box>
                    </Box>
                  </Box>
                  <Box sx={{ p: 2.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      Key Features
                    </Typography>
                    <List dense>
                      {feature.keyFeatures.slice(0, 5).map((point) => (
                        <ListItem key={point} sx={{ py: 0.2, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 20 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: feature.color }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={point}
                            primaryTypographyProps={{ variant: "body2", fontSize: "0.8rem" }}
                          />
                        </ListItem>
                      ))}
                    </List>
                    
                    <Accordion 
                      sx={{ 
                        mt: 1.5, 
                        boxShadow: "none", 
                        bgcolor: alpha(feature.color, 0.03),
                        "&:before": { display: "none" },
                        borderRadius: "8px !important",
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 40 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: feature.color }}>
                          Management Commands
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails sx={{ pt: 0 }}>
                        {feature.commands.map((cmd) => (
                          <Box key={cmd.cmd} sx={{ mb: 1 }}>
                            <Typography variant="caption" sx={{ fontFamily: "monospace", color: feature.color, fontWeight: 600 }}>
                              {cmd.cmd}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" display="block">
                              {cmd.desc}
                            </Typography>
                          </Box>
                        ))}
                      </AccordionDetails>
                    </Accordion>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            FILE SYSTEM
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Important Directories */}
        <Box id="directories">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            📁 Important Directories
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Key locations you should know on a Windows system
        </Typography>

        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#0078d4", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#0078d4", 0.1)} 0%, ${alpha("#00a2ed", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {importantDirectories.map((dir, index) => (
                <TableRow
                  key={dir.path}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#0078d4", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 600, color: "#0078d4", fontSize: "0.75rem" }}
                    >
                      {dir.path}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{dir.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={dir.purpose}
                      size="small"
                      sx={{
                        bgcolor:
                          dir.purpose === "System"
                            ? alpha("#ef4444", 0.1)
                            : dir.purpose === "User Data"
                            ? alpha("#10b981", 0.1)
                            : dir.purpose === "Applications"
                            ? alpha("#3b82f6", 0.1)
                            : alpha("#f59e0b", 0.1),
                        color:
                          dir.purpose === "System"
                            ? "#ef4444"
                            : dir.purpose === "User Data"
                            ? "#10b981"
                            : dir.purpose === "Applications"
                            ? "#3b82f6"
                            : "#f59e0b",
                        fontWeight: 600,
                        fontSize: "0.65rem",
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">{dir.notes}</Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Registry Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            REGISTRY
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Registry Keys Section */}
        <Box id="registry-keys">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🗝️ Important Registry Keys
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Security-relevant registry locations to monitor
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {registryKeys.map((regKey) => (
            <Grid item xs={12} md={6} key={regKey.key}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(
                    regKey.securityRelevance === "CRITICAL" ? "#ef4444" :
                    regKey.securityRelevance === "HIGH" ? "#f59e0b" : "#10b981", 0.2
                  )}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.1)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                  <Chip 
                    label={regKey.hive} 
                    size="small" 
                    sx={{ 
                      fontFamily: "monospace", 
                      fontWeight: 700,
                      bgcolor: alpha("#8b5cf6", 0.1),
                      color: "#8b5cf6",
                    }} 
                  />
                  <Chip
                    label={regKey.securityRelevance}
                    size="small"
                    sx={{
                      fontWeight: 700,
                      fontSize: "0.65rem",
                      bgcolor: alpha(
                        regKey.securityRelevance === "CRITICAL" ? "#ef4444" :
                        regKey.securityRelevance === "HIGH" ? "#f59e0b" :
                        regKey.securityRelevance === "MEDIUM" ? "#3b82f6" : "#10b981", 0.1
                      ),
                      color: regKey.securityRelevance === "CRITICAL" ? "#ef4444" :
                        regKey.securityRelevance === "HIGH" ? "#f59e0b" :
                        regKey.securityRelevance === "MEDIUM" ? "#3b82f6" : "#10b981",
                    }}
                  />
                </Box>
                <Typography
                  variant="body2"
                  sx={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#8b5cf6", mb: 1, wordBreak: "break-all" }}
                >
                  {regKey.key}
                </Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>{regKey.description}</Typography>
                <Typography variant="caption" color="text.secondary">
                  <WarningIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: "middle" }} />
                  {regKey.notes}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            COMMAND LINE
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Essential Commands - Grouped by Category */}
        <Box id="cmd-commands">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            ⌨️ Essential CMD Commands
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Comprehensive command reference organized by category
        </Typography>

        {commandCategories.map((category) => (
          <Box key={category} sx={{ mb: 4 }}>
            <Typography 
              variant="h6" 
              sx={{ 
                fontWeight: 700, 
                mb: 2, 
                display: "flex", 
                alignItems: "center", 
                gap: 1,
                color: "#10b981",
              }}
            >
              {category === "Navigation" && <FolderIcon sx={{ fontSize: 20 }} />}
              {category === "Files" && <FolderIcon sx={{ fontSize: 20 }} />}
              {category === "Processes" && <MemoryIcon sx={{ fontSize: 20 }} />}
              {category === "Services" && <SettingsIcon sx={{ fontSize: 20 }} />}
              {category === "Users" && <PersonIcon sx={{ fontSize: 20 }} />}
              {category === "Network" && <NetworkCheckIcon sx={{ fontSize: 20 }} />}
              {category === "Security" && <SecurityIcon sx={{ fontSize: 20 }} />}
              {category === "System" && <BuildIcon sx={{ fontSize: 20 }} />}
              {category}
            </Typography>
            <Grid container spacing={2}>
              {essentialCommands.filter(c => c.category === category).map((cmd) => (
                <Grid item xs={12} sm={6} md={4} key={cmd.command}>
                  <Paper
                    sx={{
                      p: 2,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha("#10b981", 0.15)}`,
                      transition: "all 0.2s ease",
                      "&:hover": {
                        borderColor: "#10b981",
                        transform: "translateY(-2px)",
                      },
                    }}
                  >
                    <Typography
                      variant="subtitle1"
                      sx={{ fontWeight: 700, fontFamily: "monospace", color: "#10b981", mb: 0.5, fontSize: "0.9rem" }}
                    >
                      {cmd.command}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.8rem" }}>
                      {cmd.description}
                    </Typography>
                    <Chip
                      label={cmd.example}
                      size="small"
                      sx={{
                        fontFamily: "monospace",
                        fontSize: "0.65rem",
                        bgcolor: alpha("#10b981", 0.08),
                        mb: 1,
                      }}
                    />
                    <Typography variant="caption" display="block" color="text.secondary" sx={{ fontSize: "0.7rem" }}>
                      {cmd.flags}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        ))}

        </Box>

        {/* PowerShell Comparison */}
        <Box id="powershell">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🔷 PowerShell Equivalents
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Modern PowerShell cmdlets with usage examples
        </Typography>

        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#6366f1", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>CMD</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>PowerShell Cmdlet</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Aliases</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example Usage</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {powershellCommands.map((cmd, index) => (
                <TableRow
                  key={cmd.cmd}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#8b5cf6", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600, fontSize: "0.8rem" }}>
                      {cmd.cmd}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 600, color: "#8b5cf6", fontSize: "0.8rem" }}
                    >
                      {cmd.ps}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", color: "text.secondary", fontSize: "0.75rem" }}>
                      {cmd.alias}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }}>
                      {cmd.usage}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        </Box>

        {/* PowerShell Security Commands Section */}
        <Box id="powershell-security" sx={{ mt: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🔒 PowerShell Security Commands
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Essential PowerShell cmdlets for security analysis and administration
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {powershellSecurityCommands.map((category) => (
              <Grid item xs={12} md={6} key={category.category}>
                <Paper
                  sx={{
                    p: 2,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
                  }}
                >
                  <Typography
                    variant="subtitle1"
                    sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6", display: "flex", alignItems: "center", gap: 1 }}
                  >
                    <TerminalIcon sx={{ fontSize: 20 }} />
                    {category.category}
                  </Typography>
                  {category.commands.map((cmd) => (
                    <Box
                      key={cmd.cmd}
                      sx={{
                        p: 1,
                        mb: 1,
                        borderRadius: 2,
                        bgcolor: alpha("#8b5cf6", 0.03),
                        borderLeft: `3px solid ${alpha("#8b5cf6", 0.3)}`,
                      }}
                    >
                      <Typography
                        variant="caption"
                        sx={{ fontFamily: "monospace", color: "#8b5cf6", fontWeight: 600, display: "block" }}
                      >
                        {cmd.cmd}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {cmd.desc}
                      </Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Networking Section */}
        <Box id="networking" sx={{ mt: 5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              NETWORKING
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🌐 Network Configuration
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Commands for network troubleshooting and analysis
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {networkConfiguration.map((topic) => (
              <Grid item xs={12} sm={6} md={4} key={topic.topic}>
                <Paper
                  sx={{
                    p: 2,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#06b6d4", 0.15)}`,
                    transition: "all 0.2s",
                    "&:hover": {
                      borderColor: "#06b6d4",
                    },
                  }}
                >
                  <Typography
                    variant="subtitle1"
                    sx={{ fontWeight: 700, mb: 2, color: "#06b6d4", display: "flex", alignItems: "center", gap: 1 }}
                  >
                    <NetworkCheckIcon sx={{ fontSize: 20 }} />
                    {topic.topic}
                  </Typography>
                  {topic.commands.map((cmd) => (
                    <Box key={cmd.cmd} sx={{ mb: 1 }}>
                      <Typography
                        variant="caption"
                        sx={{ fontFamily: "monospace", color: "#06b6d4", fontWeight: 600, display: "block" }}
                      >
                        {cmd.cmd}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {cmd.desc}
                      </Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Common Ports Section */}
        <Box id="common-ports">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🔌 Common Windows Ports
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Important ports to know for Windows networking and security
          </Typography>

          <TableContainer
            component={Paper}
            sx={{
              mb: 5,
              borderRadius: 4,
              border: `1px solid ${alpha("#f59e0b", 0.15)}`,
            }}
          >
            <Table size="small">
              <TableHead>
                <TableRow
                  sx={{
                    background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.1)} 0%, ${alpha("#f97316", 0.1)} 100%)`,
                  }}
                >
                  <TableCell sx={{ fontWeight: 700 }}>Port</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Service</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {commonPorts.map((port, index) => (
                  <TableRow
                    key={port.port}
                    sx={{
                      bgcolor: index % 2 === 0 ? "transparent" : alpha("#f59e0b", 0.02),
                    }}
                  >
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: "monospace", fontWeight: 700, color: "#f59e0b", fontSize: "0.85rem" }}
                      >
                        {port.port}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={port.protocol} size="small" sx={{ fontSize: "0.7rem", fontWeight: 600 }} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.85rem" }}>
                        {port.service}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" color="text.secondary">
                        {port.notes}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>

        {/* Active Directory Section */}
        <Box id="active-directory" sx={{ mt: 5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              ACTIVE DIRECTORY
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🏢 Active Directory Basics
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Fundamental concepts of Windows domain environments
          </Typography>

          <Grid container spacing={2} sx={{ mb: 5 }}>
            {activeDirectoryBasics.map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.component}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#3b82f6", 0.15)}`,
                    transition: "all 0.2s",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      borderColor: "#3b82f6",
                    },
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                    {item.component}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, fontSize: "0.85rem" }}>
                    {item.description}
                  </Typography>
                  <List dense>
                    {item.keyPoints.map((point) => (
                      <ListItem key={point} sx={{ py: 0.2, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 20 }}>
                          <CheckCircleIcon sx={{ fontSize: 12, color: "#3b82f6" }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={point}
                          primaryTypographyProps={{ variant: "caption", fontSize: "0.75rem" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Group Policy Section */}
        <Box id="group-policy" sx={{ mt: 5 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            📋 Group Policy Settings
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Important security-related Group Policy configurations
          </Typography>

          {groupPolicySettings.map((category) => (
            <Accordion
              key={category.category}
              sx={{
                mb: 2,
                borderRadius: 3,
                "&:before": { display: "none" },
                border: `1px solid ${alpha("#10b981", 0.2)}`,
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                sx={{ bgcolor: alpha("#10b981", 0.05) }}
              >
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {category.category}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }}>
                    {category.path}
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700 }}>Setting</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Recommended</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Risk if Misconfigured</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {category.settings.map((setting) => (
                      <TableRow key={setting.name}>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontSize: "0.85rem" }}>{setting.name}</Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={setting.recommended}
                            size="small"
                            sx={{ bgcolor: alpha("#10b981", 0.1), color: "#10b981", fontWeight: 600, fontSize: "0.7rem" }}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="error">
                            <WarningIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: "middle" }} />
                            {setting.risk}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>

        {/* Important Processes Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PROCESSES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Processes Section */}
        <Box id="processes">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            ⚙️ Critical Windows Processes
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Know these processes - suspicious variations often indicate compromise
        </Typography>

        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)} 0%, ${alpha("#f97316", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>Process</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>PID</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Parent</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Security Notes</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {importantProcesses.map((proc, index) => (
                <TableRow
                  key={proc.process}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#ef4444", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 700, color: "#ef4444", fontSize: "0.8rem" }}
                    >
                      {proc.process}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{proc.pid}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                      {proc.parent}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{proc.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">
                      <BugReportIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: "middle" }} />
                      {proc.notes}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Security Events Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            EVENT LOGS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Security Events Section */}
        <Box id="security-events">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            📋 Security Event IDs
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Key Windows Security Log events for detection and forensics
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          {securityEventIds.map((evt) => (
            <Grid item xs={12} sm={6} md={4} key={evt.eventId}>
              <Paper
                sx={{
                  p: 2,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha("#06b6d4", 0.15)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    borderColor: "#06b6d4",
                  },
                }}
              >
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography
                    variant="h6"
                    sx={{ fontFamily: "monospace", fontWeight: 800, color: "#06b6d4" }}
                  >
                    {evt.eventId}
                  </Typography>
                  <Chip 
                    label={evt.category} 
                    size="small"
                    sx={{ 
                      fontSize: "0.65rem",
                      fontWeight: 600,
                      bgcolor: alpha("#06b6d4", 0.1),
                      color: "#06b6d4",
                    }}
                  />
                </Box>
                <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                  {evt.description}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {evt.notes}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Additional Security Events */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Additional Important Event IDs
        </Typography>
        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow sx={{ background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#0891b2", 0.1)} 100%)` }}>
                <TableCell sx={{ fontWeight: 700 }}>Event ID</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Security Relevance</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {additionalSecurityEvents.map((evt, index) => (
                <TableRow key={evt.eventId} sx={{ bgcolor: index % 2 === 0 ? "transparent" : alpha("#06b6d4", 0.02) }}>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4" }}>
                      {evt.eventId}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontWeight: 600, fontSize: "0.85rem" }}>{evt.description}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={evt.category} size="small" sx={{ fontSize: "0.65rem", fontWeight: 600 }} />
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" color="text.secondary">{evt.notes}</Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Keyboard Shortcuts */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PRODUCTIVITY
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Shortcuts Section */}
        <Box id="shortcuts">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            ⌨️ Essential Keyboard Shortcuts
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Speed up your Windows workflow with these key combinations
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {keyboardShortcuts.map((shortcut) => (
            <Grid item xs={6} sm={4} md={3} key={shortcut.shortcut}>
              <Paper
                sx={{
                  p: 2,
                  textAlign: "center",
                  borderRadius: 3,
                  border: `1px solid ${alpha("#f59e0b", 0.15)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    transform: "translateY(-2px)",
                    bgcolor: alpha("#f59e0b", 0.03),
                  },
                }}
              >
                <Chip
                  label={shortcut.shortcut}
                  sx={{
                    fontFamily: "monospace",
                    fontWeight: 700,
                    fontSize: "0.75rem",
                    bgcolor: alpha("#f59e0b", 0.1),
                    color: "#f59e0b",
                    mb: 1,
                  }}
                />
                <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>
                  {shortcut.action}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Windows Tools Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            TOOLS
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        </Box>

        {/* Tools Section */}
        <Box id="tools">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🛠️ Essential Windows Tools
          </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Built-in and Sysinternals tools every admin should know
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {["Built-in", "Sysinternals"].map((category) => (
            <Grid item xs={12} md={6} key={category}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 4,
                  border: `1px solid ${alpha(category === "Built-in" ? "#3b82f6" : "#8b5cf6", 0.2)}`,
                  height: "100%",
                }}
              >
                <Typography 
                  variant="h6" 
                  sx={{ 
                    fontWeight: 700, 
                    mb: 2, 
                    color: category === "Built-in" ? "#3b82f6" : "#8b5cf6",
                    display: "flex",
                    alignItems: "center",
                    gap: 1,
                  }}
                >
                  <BuildIcon sx={{ fontSize: 20 }} />
                  {category} Tools
                </Typography>
                <Grid container spacing={1}>
                  {windowsTools.filter(t => t.category === category).map((tool) => (
                    <Grid item xs={12} key={tool.tool}>
                      <Box
                        sx={{
                          p: 1.5,
                          borderRadius: 2,
                          bgcolor: alpha(category === "Built-in" ? "#3b82f6" : "#8b5cf6", 0.03),
                          borderLeft: `3px solid ${category === "Built-in" ? "#3b82f6" : "#8b5cf6"}`,
                        }}
                      >
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{tool.tool}</Typography>
                          <Chip 
                            label={tool.command} 
                            size="small" 
                            sx={{ 
                              fontFamily: "monospace", 
                              fontSize: "0.65rem",
                              bgcolor: alpha(category === "Built-in" ? "#3b82f6" : "#8b5cf6", 0.1),
                              color: category === "Built-in" ? "#3b82f6" : "#8b5cf6",
                            }} 
                          />
                        </Box>
                        <Typography variant="caption" color="text.secondary">{tool.description}</Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          ))}
        </Grid>

        </Box>

        {/* Environment Variables Section */}
        <Box id="environment-vars">
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🔤 Environment Variables
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          System and user environment variables you'll encounter frequently
        </Typography>

        <TableContainer
          component={Paper}
          sx={{
            mb: 5,
            borderRadius: 4,
            border: `1px solid ${alpha("#06b6d4", 0.15)}`,
          }}
        >
          <Table size="small">
            <TableHead>
              <TableRow
                sx={{
                  background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#0891b2", 0.1)} 100%)`,
                }}
              >
                <TableCell sx={{ fontWeight: 700 }}>Variable</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example Value</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {environmentVariables.map((env, index) => (
                <TableRow
                  key={env.variable}
                  sx={{
                    bgcolor: index % 2 === 0 ? "transparent" : alpha("#06b6d4", 0.02),
                  }}
                >
                  <TableCell>
                    <Typography
                      variant="body2"
                      sx={{ fontFamily: "monospace", fontWeight: 700, color: "#06b6d4", fontSize: "0.8rem" }}
                    >
                      {env.variable}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                      {env.example}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontSize: "0.8rem" }}>{env.description}</Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        </Box>

        {/* Forensic Artifacts Section */}
        <Box id="forensic-artifacts" sx={{ mt: 5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              FORENSICS
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🔍 Forensic Artifacts
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Key locations and files for Windows forensic analysis
          </Typography>

          {forensicArtifacts.map((category) => (
            <Accordion
              key={category.category}
              sx={{
                mb: 2,
                borderRadius: 3,
                "&:before": { display: "none" },
                border: `1px solid ${alpha("#ec4899", 0.2)}`,
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                sx={{ bgcolor: alpha("#ec4899", 0.05) }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <FindInPageIcon sx={{ color: "#ec4899", fontSize: 20 }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    {category.category}
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {category.artifacts.map((artifact) => (
                    <Grid item xs={12} sm={6} key={artifact.name}>
                      <Paper
                        sx={{
                          p: 2,
                          bgcolor: alpha("#ec4899", 0.02),
                          borderLeft: `3px solid ${alpha("#ec4899", 0.3)}`,
                        }}
                      >
                        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                          {artifact.name}
                        </Typography>
                        <Typography
                          variant="caption"
                          sx={{
                            fontFamily: "monospace",
                            color: "#ec4899",
                            display: "block",
                            mb: 0.5,
                            wordBreak: "break-all",
                            fontSize: "0.65rem",
                          }}
                        >
                          {artifact.location}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {artifact.description}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>

        {/* Hardening Checklist Section */}
        <Box id="hardening" sx={{ mt: 5 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
            <Divider sx={{ flex: 1 }} />
            <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
              HARDENING
            </Typography>
            <Divider sx={{ flex: 1 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            🛡️ Windows Hardening Checklist
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Essential security hardening measures for Windows systems
          </Typography>

          <Grid container spacing={2}>
            {hardeningChecklist.map((category) => (
              <Grid item xs={12} md={6} key={category.category}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha("#22c55e", 0.15)}`,
                    transition: "all 0.2s",
                    "&:hover": {
                      borderColor: "#22c55e",
                    },
                  }}
                >
                  <Typography
                    variant="subtitle1"
                    sx={{ fontWeight: 700, mb: 2, color: "#22c55e", display: "flex", alignItems: "center", gap: 1 }}
                  >
                    <VerifiedUserIcon sx={{ fontSize: 20 }} />
                    {category.category}
                  </Typography>
                  <List dense>
                    {category.items.map((item, index) => (
                      <ListItem key={index} sx={{ py: 0.3, px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ fontSize: 14, color: "#22c55e" }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={item}
                          primaryTypographyProps={{ variant: "body2", fontSize: "0.85rem" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Box>

        {/* Pro Tips - Enhanced */}
        <Box id="pro-tips" sx={{ mt: 5 }}>
          <Paper
            sx={{
              p: 3,
              mb: 5,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.05)} 0%, ${alpha("#f59e0b", 0.02)} 100%)`,
              border: `1px solid ${alpha("#f59e0b", 0.2)}`,
            }}
          >
            <Typography
              variant="h6"
              sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}
            >
              <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} />
              Pro Tips for Security Professionals
            </Typography>
          <Grid container spacing={2}>
            {[
              "Use Win+R to open the Run dialog for quick access to commands like mmc, regedit, services.msc",
              "Press Tab in CMD/PowerShell for auto-completion of commands and paths",
              "Use 'runas /user:Administrator cmd' to run commands as admin without UAC popup",
              "PowerShell's Get-Help -Full and Get-Member are your friends for learning cmdlets",
              "Enable PowerShell Script Block Logging for security monitoring",
              "Use Process Monitor (procmon) from Sysinternals for deep system analysis",
              "Run 'wmic startup list full' to see all autostart programs",
              "Use 'netsh advfirewall show allprofiles' to check firewall status",
              "Enable command-line auditing (Event 4688) in Group Policy for process tracking",
              "Always check digital signatures with 'sigcheck' from Sysinternals",
            ].map((tip, i) => (
              <Grid item xs={12} sm={6} key={i}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <CheckCircleIcon sx={{ fontSize: 18, color: "#f59e0b", mt: 0.3, flexShrink: 0 }} />
                  <Typography variant="body2">{tip}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Security Warning */}
        <Alert 
          severity="warning" 
          icon={<WarningIcon />}
          sx={{ mb: 4, borderRadius: 3 }}
        >
          <AlertTitle sx={{ fontWeight: 700 }}>Security Reminder</AlertTitle>
          Always practice these skills in authorized environments only. Many techniques covered here 
          are used for both system administration and attack detection. Never use these skills on 
          systems you don't have explicit permission to test.
        </Alert>

          {/* Related Learning */}
          <Paper
            sx={{
              p: 3,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, transparent 100%)`,
              border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
            }}
          >
            <Typography
              variant="h6"
              sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}
            >
              <SchoolIcon sx={{ color: theme.palette.primary.main }} />
              Continue Learning
            </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Build on these fundamentals with more advanced topics
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="Windows Internals for RE →"
              clickable
              onClick={() => navigate("/learn/windows-internals")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Privilege Escalation →"
              clickable
              onClick={() => navigate("/learn/privilege-escalation")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Commands Reference →"
              clickable
              onClick={() => navigate("/learn/commands")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Active Directory Basics →"
              clickable
              onClick={() => navigate("/learn/active-directory")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="PowerShell for Security →"
              clickable
              onClick={() => navigate("/learn/powershell-security")}
              sx={{ fontWeight: 600 }}
            />
          </Box>
          </Paper>
        </Box>

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="Windows Fundamentals Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>
        </Container>
      </Box>

      {/* Floating Action Buttons */}
      <Fab
        color="primary"
        onClick={() => setNavDrawerOpen(true)}
        sx={{
          position: "fixed",
          bottom: 90,
          right: 24,
          zIndex: 1000,
          bgcolor: accent,
          "&:hover": { bgcolor: "#005a9e" },
          boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
          display: { xs: "flex", lg: "none" },
        }}
      >
        <ListAltIcon />
      </Fab>

      {/* Scroll to Top FAB */}
      <Fab
        size="small"
        onClick={scrollToTop}
        sx={{
          position: "fixed",
          bottom: 32,
          right: 28,
          zIndex: 1000,
          bgcolor: alpha(accent, 0.15),
          color: accent,
          "&:hover": { bgcolor: alpha(accent, 0.25) },
          display: { xs: "flex", lg: "none" },
        }}
      >
        <KeyboardArrowUpIcon />
      </Fab>

      {/* Navigation Drawer for Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.08),
                  },
                  transition: "all 0.15s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, color: activeSection === item.id ? accent : "text.secondary" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

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
    </LearnPageLayout>
  );
}
