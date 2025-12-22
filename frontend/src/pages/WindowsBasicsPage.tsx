import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
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
} from "@mui/material";
import { useNavigate } from "react-router-dom";
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
];

export default function WindowsBasicsPage() {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `Windows Fundamentals learning page - Comprehensive guide to the Microsoft Windows operating system for security professionals, system administrators, and IT practitioners. This in-depth resource covers core concepts including the NTFS file system, Windows Registry, Services architecture, Users & Permissions model, Command Line interfaces (CMD and PowerShell), and Process/Memory management. Includes detailed reference tables for important directory locations, security-critical registry keys, essential CMD commands with PowerShell equivalents, critical system processes, Windows Security Event IDs for detection and forensics, and productivity keyboard shortcuts.`;

  const commandCategories = [...new Set(essentialCommands.map(c => c.category))];

  return (
    <LearnPageLayout pageTitle="Windows Fundamentals" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Back Button */}
        <Chip
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          onClick={() => navigate("/learn")}
          sx={{ mb: 3, fontWeight: 600 }}
          clickable
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

        {/* Boot Process Section */}
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

        {/* Core Concepts */}
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

        {/* Section Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            FILE SYSTEM
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Important Directories */}
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

        {/* Essential Commands - Grouped by Category */}
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

        {/* PowerShell Comparison */}
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

        {/* Important Processes Section */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PROCESSES
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

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

        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          📋 Security Event IDs
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Key Windows Security Log events for detection and forensics
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
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

        {/* Keyboard Shortcuts */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700, letterSpacing: 2 }}>
            PRODUCTIVITY
          </Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

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

        {/* Environment Variables Section */}
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

        {/* Pro Tips - Enhanced */}
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
      </Container>
    </LearnPageLayout>
  );
}
